const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');
const nodemailer = require('nodemailer');
const app = express();

const PORT = process.env.PORT || 3000;
const DATA_FILE = 'data.json';
const ENV_FILE = '.env';
const UPLOADS_DIR = path.join(__dirname, 'uploads');
app.use(express.static(__dirname));

// Ensure uploads folder exists
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// ─────────────────────────────────────────────────────────────────────────────
//  ENCRYPTION SETUP  (AES-256-GCM — authenticated encryption)
//  Key source : DTVS_SECRET in .env file, auto-generated on first run
// ─────────────────────────────────────────────────────────────────────────────
const ALGO = 'aes-256-gcm';
const IV_LEN = 12; // 96-bit IV recommended for GCM

function loadOrCreateKey() {
    let dataKey, sessionSecret;
    let lines = [];

    if (fs.existsSync(ENV_FILE)) {
        lines = fs.readFileSync(ENV_FILE, 'utf8').split('\n');
    }

    const keyLine = lines.find(l => l.startsWith('DTVS_SECRET='));
    const sessionLine = lines.find(l => l.startsWith('SESSION_SECRET='));

    dataKey = keyLine ? keyLine.split('=')[1].trim() : null;
    sessionSecret = sessionLine ? sessionLine.split('=')[1].trim() : null;

    let changed = false;

    if (!dataKey || dataKey.length !== 64) {
        dataKey = crypto.randomBytes(32).toString('hex');
        changed = true;
        console.log('✅  New data encryption key generated.');
    }
    if (!sessionSecret || sessionSecret.length < 64) {
        sessionSecret = crypto.randomBytes(48).toString('hex');
        changed = true;
        console.log('✅  New session secret generated.');
    }

    if (changed) {
        const kept = lines.filter(l =>
            !l.startsWith('DTVS_SECRET=') && !l.startsWith('SESSION_SECRET=') && l.trim()
        );
        kept.push(`DTVS_SECRET=${dataKey}`, `SESSION_SECRET=${sessionSecret}`);
        fs.writeFileSync(ENV_FILE, kept.join('\n') + '\n');
    }

    return { dataKey: Buffer.from(dataKey, 'hex'), sessionSecret };
}

const { dataKey: SECRET_KEY, sessionSecret: SESSION_SECRET } = loadOrCreateKey();

// ── Data-field encryption helpers ─────────────────────────────────────────────
function encrypt(plaintext) {
    if (plaintext === undefined || plaintext === null || plaintext === '') return plaintext;
    const iv = crypto.randomBytes(IV_LEN);
    const cipher = crypto.createCipheriv(ALGO, SECRET_KEY, iv);
    const enc = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `${iv.toString('hex')}:${tag.toString('hex')}:${enc.toString('hex')}`;
}

function decrypt(token) {
    if (!token || !String(token).includes(':')) return token;
    try {
        const parts = String(token).split(':');
        if (parts.length !== 3) return token;
        const [ivHex, tagHex, encHex] = parts;
        const iv = Buffer.from(ivHex, 'hex');
        const tag = Buffer.from(tagHex, 'hex');
        const encData = Buffer.from(encHex, 'hex');
        const decipher = crypto.createDecipheriv(ALGO, SECRET_KEY, iv);
        decipher.setAuthTag(tag);
        return decipher.update(encData) + decipher.final('utf8');
    } catch (e) {
        console.error('Decryption error:', e.message);
        return token;
    }
}

// ── rack is intentionally NOT encrypted (short location code, low sensitivity) ──
const STOCK_ENC_FIELDS = ['name', 'partNumber', 'supplier', 'supplierContact', 'price', 'category', 'qtyPerMachine'];
const HISTORY_ENC_FIELDS = ['name', 'partNumber', 'giver', 'taker', 'comment'];

function encryptStock(item) { const e = { ...item }; STOCK_ENC_FIELDS.forEach(f => { if (e[f] !== undefined) e[f] = encrypt(e[f]); }); return e; }
function decryptStock(item) { const d = { ...item }; STOCK_ENC_FIELDS.forEach(f => { if (d[f] !== undefined) d[f] = decrypt(d[f]); }); return d; }
function encryptHistory(r) { const e = { ...r }; HISTORY_ENC_FIELDS.forEach(f => { if (e[f] !== undefined) e[f] = encrypt(e[f]); }); return e; }
function decryptHistory(r) { const d = { ...r }; HISTORY_ENC_FIELDS.forEach(f => { if (d[f] !== undefined) d[f] = decrypt(d[f]); }); return d; }

// ─────────────────────────────────────────────────────────────────────────────
//  PASSWORD HASHING  (PBKDF2 — built-in crypto, no extra packages needed)
//  Format stored: "pbkdf2:<salt_hex>:<hash_hex>"
// ─────────────────────────────────────────────────────────────────────────────
const PBKDF2_ITERATIONS = 200_000;
const PBKDF2_KEYLEN = 64;
const PBKDF2_DIGEST = 'sha512';

function hashPassword(password) {
    const salt = crypto.randomBytes(32).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST).toString('hex');
    return `pbkdf2:${salt}:${hash}`;
}

function verifyPassword(password, stored) {
    // Support legacy plain-text passwords (migration path)
    if (!stored.startsWith('pbkdf2:')) {
        return password === stored; // plain-text match (will be re-hashed on next save)
    }
    const [, salt, expectedHash] = stored.split(':');
    const actualHash = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST).toString('hex');
    // Constant-time comparison to prevent timing attacks
    return crypto.timingSafeEqual(Buffer.from(actualHash, 'hex'), Buffer.from(expectedHash, 'hex'));
}

// ─────────────────────────────────────────────────────────────────────────────
//  DATA LAYER  (write-through in-memory cache — fix #1: race condition)
// ─────────────────────────────────────────────────────────────────────────────
const EMPTY_DB = () => ({ users: [], stock: [], restockHistory: [], withdrawalHistory: [], adminEmail: '', auditLog: [] });

function logAudit(data, action, performedBy, detail = '') {
    if (!data.auditLog) data.auditLog = [];
    data.auditLog.push({ ts: new Date().toISOString(), action, performedBy, detail });
    if (data.auditLog.length > 500) data.auditLog = data.auditLog.slice(-500); // keep last 500
}

let _dbCache = null; // in-memory cache; null = not loaded yet

function getData() {
    if (_dbCache) return _dbCache; // serve from cache
    if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, JSON.stringify(EMPTY_DB(), null, 2));
    const raw = JSON.parse(fs.readFileSync(DATA_FILE));
    _dbCache = {
        ...raw,
        stock: (raw.stock || []).map(decryptStock),
        restockHistory: (raw.restockHistory || []).map(decryptHistory),
        withdrawalHistory: (raw.withdrawalHistory || []).map(decryptHistory),
    };
    return _dbCache;
}

const BACKUP_DIR = path.join(__dirname, 'backups');
if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR);

function saveData(data) {
    _dbCache = data; // update cache first
    // Rolling backup — keep last 5 versions
    try {
        if (fs.existsSync(DATA_FILE)) {
            const stamp = new Date().toISOString().replace(/[:.]/g, '_').slice(0, 19);
            const bkp = path.join(BACKUP_DIR, `data_${stamp}.json`);
            fs.copyFileSync(DATA_FILE, bkp);
            const files = fs.readdirSync(BACKUP_DIR)
                .filter(f => f.startsWith('data_') && f.endsWith('.json'))
                .sort();
            if (files.length > 5) files.slice(0, files.length - 5).forEach(f => fs.unlinkSync(path.join(BACKUP_DIR, f)));
        }
    } catch (e) { console.error('Backup error:', e.message); }
    const toWrite = {
        ...data,
        stock: (data.stock || []).map(encryptStock),
        restockHistory: (data.restockHistory || []).map(encryptHistory),
        withdrawalHistory: (data.withdrawalHistory || []).map(encryptHistory),
    };
    fs.writeFileSync(DATA_FILE, JSON.stringify(toWrite, null, 2));
}

// ─────────────────────────────────────────────────────────────────────────────
//  EXPRESS SETUP
// ─────────────────────────────────────────────────────────────────────────────
// Skip express.json() for the upload route — it drains the raw body stream,
// which would leave nothing for the multipart parser to read.
app.use((req, res, next) => {
    if (req.path === '/api/documents/upload') return next();
    express.json({ limit: '1mb' })(req, res, next);
});
app.use(express.static('.'));
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 8 * 60 * 60 * 1000,
        // secure: true,  // Uncomment when served over HTTPS
    }
}));

const deletedUserIds = new Set(); // fix #4: active sessions of deleted users are rejected

// ─────────────────────────────────────────────────────────────────────────────
//  AUTH MIDDLEWARE
// ─────────────────────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
    if (!req.session || !req.session.user) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    // fix #4: reject sessions belonging to deleted users
    if (deletedUserIds && deletedUserIds.has(req.session.user.id)) {
        req.session.destroy(() => { });
        return res.status(401).json({ error: 'Session invalidated' });
    }
    next();
}

function requireAdmin(req, res, next) {
    if (!req.session || !req.session.user || req.session.user.role !== 'superadmin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
}

// ─────────────────────────────────────────────────────────────────────────────
//  INPUT VALIDATION HELPERS
// ─────────────────────────────────────────────────────────────────────────────
function sanitizeString(val, maxLen = 500) {
    if (typeof val !== 'string') return '';
    return val.trim().slice(0, maxLen);
}

function safeInt(val, fallback = 0) {
    const n = parseInt(val, 10);
    return isFinite(n) ? n : fallback;
}

function safeFloat(val, fallback = '') {
    if (val === '' || val === undefined || val === null) return fallback;
    const n = parseFloat(val);
    return isFinite(n) ? n : fallback;
}

// ─────────────────────────────────────────────────────────────────────────────
//  NODEMAILER
// ─────────────────────────────────────────────────────────────────────────────
function getMailCredentials() {
    const envLines = fs.existsSync(ENV_FILE)
        ? fs.readFileSync(ENV_FILE, 'utf8').split('\n') : [];
    const get = key => {
        const l = envLines.find(line => line.startsWith(key + '='));
        return l ? l.split('=').slice(1).join('=').trim() : process.env[key] || '';
    };
    return { user: get('MAIL_USER'), pass: get('MAIL_PASS') };
}

function createTransporter() {
    const { user, pass } = getMailCredentials();
    if (!user || !pass) {
        console.warn('⚠️  MAIL_USER / MAIL_PASS not set in .env — email sending disabled.');
        return null;
    }
    return nodemailer.createTransport({ service: 'gmail', auth: { user, pass } });
}

async function sendMail(subject, html) {
    const transporter = createTransporter();
    if (!transporter) return;
    const data = getData();
    if (!data.adminEmail) { console.warn('No admin email configured.'); return; }
    const { user } = getMailCredentials();
    try {
        await transporter.sendMail({
            from: `"DTVS Champion" <${user}>`,
            to: data.adminEmail,
            subject, html
        });
    } catch (err) {
        console.error('Email send error:', err.message);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  RATE LIMITING
// ─────────────────────────────────────────────────────────────────────────────
const loginAttempts = new Map();

function checkRateLimit(ip) {
    const now = Date.now();
    const WINDOW = 15 * 60 * 1000;
    const MAX = 10;

    let entry = loginAttempts.get(ip);
    if (!entry || now > entry.resetAt) {
        entry = { count: 0, resetAt: now + WINDOW };
        loginAttempts.set(ip, entry);
    }
    entry.count++;
    if (entry.count > MAX) return false;
    return true;
}

function resetRateLimit(ip) {
    loginAttempts.delete(ip);
}

// ─────────────────────────────────────────────────────────────────────────────
//  ROUTES
// ─────────────────────────────────────────────────────────────────────────────

// LOGIN
app.post('/api/login', (req, res) => {
    const ip = req.ip || req.socket.remoteAddress;
    if (!checkRateLimit(ip)) {
        return res.status(429).json({ error: 'Too many login attempts. Try again in 15 minutes.' });
    }

    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });

    const data = getData();
    const user = data.users.find(u => u.username === username);

    if (!user || !verifyPassword(password, user.password)) {
        return res.status(401).json({ error: 'Invalid username or password' });
    }

    if (!user.password.startsWith('pbkdf2:')) {
        const idx = data.users.findIndex(u => u.username === username);
        data.users[idx].password = hashPassword(password);
        saveData(data);
    }

    resetRateLimit(ip);

    req.session.regenerate(err => {
        if (err) return res.status(500).json({ error: 'Session error' });
        const safeUser = { id: user.id, username: user.username, role: user.role, permissions: user.permissions };
        req.session.user = safeUser;
        // FIX #13 — Remember Me: extend cookie to 30 days if requested
        if (req.body.rememberMe) req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;
        res.json({ success: true, user: safeUser });
    });
});

// LOGOUT
app.post('/api/logout', (req, res) => {
    req.session.destroy(() => res.json({ success: true }));
});

// All routes below require authentication
app.use('/api', requireAuth);

// ── Stock ──────────────────────────────────────────────────────────────────
app.post('/api/add-item', requireAdmin, (req, res) => {
    const data = getData();
    const newItem = {
        id: Date.now(),
        name: sanitizeString(req.body.name),
        partNumber: sanitizeString(req.body.partNumber),
        quantity: safeInt(req.body.quantity),
        criticalLimit: safeInt(req.body.criticalLimit),
        category: sanitizeString(req.body.category) || 'General',
        supplier: sanitizeString(req.body.supplier),
        supplierContact: sanitizeString(req.body.supplierContact),
        qtyPerMachine: sanitizeString(req.body.qtyPerMachine),
        price: safeFloat(req.body.price),
        rack: sanitizeString(req.body.rack || '', 100),  // ← NEW: rack location
    };
    if (!newItem.name) return res.status(400).json({ error: 'Name is required' });
    data.stock.push(newItem);
    logAudit(data, 'ADD_ITEM', req.session.user.username, `${newItem.name} (${newItem.partNumber})`);
    saveData(data);
    res.json({ success: true, item: newItem });
});

// ── Bulk add items (used by XLS import — fix #2: single round-trip) ──────────
app.post('/api/bulk-add-items', requireAdmin, (req, res) => {
    const { items } = req.body;
    if (!Array.isArray(items) || items.length === 0)
        return res.status(400).json({ error: 'No items provided' });

    const data = getData();
    const added = [], skipped = [], failed = [];

    for (const item of items) {
        if (!item.name) { failed.push(item.partNumber || '?'); continue; }
        // Skip duplicate part numbers
        const dup = data.stock.find(s =>
            item.partNumber && s.partNumber &&
            s.partNumber.trim().toLowerCase() === String(item.partNumber).trim().toLowerCase()
        );
        if (dup) { skipped.push(item.partNumber); continue; }

        data.stock.push({
            id: Date.now() + Math.random(),
            name: sanitizeString(item.name),
            partNumber: sanitizeString(item.partNumber || ''),
            quantity: safeInt(item.quantity),
            criticalLimit: safeInt(item.criticalLimit),
            category: sanitizeString(item.category || 'General'),
            supplier: sanitizeString(item.supplier || ''),
            supplierContact: sanitizeString(item.supplierContact || ''),
            qtyPerMachine: sanitizeString(item.qtyPerMachine || ''),
            price: safeFloat(item.price),
            rack: sanitizeString(item.rack || '', 100),
        });
        added.push(item.partNumber || item.name);
    }
    saveData(data);
    res.json({ success: true, added: added.length, skipped: skipped.length, failed: failed.length });
});

// FIX #2 — Bulk add items (single server round-trip for XLS import)
app.post('/api/update-stock', (req, res) => {
    const { id, amount, type, details } = req.body;
    const data = getData();
    const item = data.stock.find(s => s.id == id);
    if (!item) return res.status(404).json({ error: 'Item not found' });

    const qty = safeInt(amount);
    if (qty <= 0) return res.status(400).json({ error: 'Quantity must be positive' });

    const timestamp = new Date().toLocaleString();
    const performedBy = req.session.user.username;

    if (type === 'withdraw') {
        if (item.quantity < qty) return res.status(400).json({ error: `Insufficient stock — only ${item.quantity} in stock` });
        if (item.quantity - qty < 0) return res.status(400).json({ error: 'Withdrawal would result in negative stock' });
        item.quantity -= qty;
        data.withdrawalHistory.push({
            dateTime: timestamp,
            name: item.name,
            partNumber: item.partNumber,
            qty,
            giver: sanitizeString((details || {}).giver || '', 200),
            taker: sanitizeString((details || {}).taker || '', 200),
            comment: sanitizeString((details || {}).comment || '', 500),
            performedBy,
        });

        if (item.quantity <= (item.criticalLimit || 0)) {
            const requiredQty = (item.criticalLimit - item.quantity) + 1;
            sendMail(
                `🚨 AUTO-PR: ${item.name}`,
                `<h3 style="font-family:Arial,sans-serif;color:#d9534f;">AUTOMATIC Purchase Request</h3>
                 <table border="1" cellpadding="8" style="border-collapse:collapse;width:100%;">
                     <thead><tr><th>Name</th><th>Part Number</th><th>Qty to Order</th></tr></thead>
                     <tbody><tr><td>${item.name}</td><td>${item.partNumber}</td><td>${requiredQty}</td></tr></tbody>
                 </table>`
            );
        }
    } else if (type === 'receive') {
        item.quantity += qty;
        data.restockHistory.push({
            dateTime: timestamp,
            name: item.name,
            partNumber: item.partNumber,
            qty,
            performedBy,
        });
    } else {
        return res.status(400).json({ error: 'Invalid type' });
    }

    saveData(data);
    res.json({ success: true });
});

app.post('/api/send-pr', (req, res) => {
    const { items } = req.body;
    if (!Array.isArray(items) || items.length === 0)
        return res.status(400).json({ error: 'No items provided' });

    const tableRows = items.map((item, idx) => `
        <tr>
            <td>${idx + 1}</td>
            <td>${sanitizeString(String(item.name))}</td>
            <td>${sanitizeString(String(item.partNumber))}</td>
            <td>${safeInt(item.qty)}</td>
            <td>${safeFloat(item.price, 0)}</td>
        </tr>`).join('');

    sendMail(
        `📝 Bulk PR Request - ${items.length} Items`,
        `<h3>Manual Purchase Request</h3>
         <table border="1" cellpadding="8" style="border-collapse:collapse;width:100%;">
             <thead style="background-color:#333;color:#fff;">
                 <tr><th>#</th><th>Name</th><th>Part Number</th><th>Qty</th><th>Price</th></tr>
             </thead>
             <tbody>${tableRows}</tbody>
         </table>`
    ).then(() => res.json({ success: true }))
        .catch(err => { console.error(err); res.status(500).json({ error: 'Mail error' }); });
});

app.post('/api/edit-item', requireAdmin, (req, res) => {
    const { id, updatedItem } = req.body;
    const data = getData();
    const index = data.stock.findIndex(s => s.id == id);
    if (index === -1) return res.status(404).json({ error: 'Item not found' });
    data.stock[index] = {
        ...data.stock[index],
        name: sanitizeString(updatedItem.name || data.stock[index].name),
        supplier: sanitizeString(updatedItem.supplier || ''),
        supplierContact: sanitizeString(updatedItem.supplierContact || ''),
        qtyPerMachine: sanitizeString(String(updatedItem.qtyPerMachine ?? '')),
        criticalLimit: safeInt(updatedItem.criticalLimit),
        price: safeFloat(updatedItem.price),
        rack: sanitizeString(updatedItem.rack || '', 100),  // ← NEW: rack location
    };
    logAudit(data, 'EDIT_ITEM', req.session.user.username, `id=${id}`);
    saveData(data);
    res.json({ success: true });
});

// ── NEW: Inline rack update endpoint (used by Update & BOM tabs) ──────────────
app.post('/api/update-rack', requireAuth, (req, res) => {
    const { id, rack } = req.body;
    const data = getData();
    const index = data.stock.findIndex(s => s.id == id);
    if (index === -1) return res.status(404).json({ error: 'Item not found' });
    data.stock[index].rack = sanitizeString(rack || '', 100);
    saveData(data);
    res.json({ success: true });
});

app.post('/api/delete-item', requireAdmin, (req, res) => {
    const data = getData();
    const before = data.stock.length;
    const toDelete = data.stock.find(s => s.id == req.body.id);
    data.stock = data.stock.filter(s => s.id != req.body.id);
    if (data.stock.length === before) return res.status(404).json({ error: 'Item not found' });
    logAudit(data, 'DELETE_ITEM', req.session.user.username, toDelete ? `${toDelete.name}` : `id=${req.body.id}`);
    saveData(data);
    res.json({ success: true });
});

// ── Users ──────────────────────────────────────────────────────────────────
app.post('/api/create-user', requireAdmin, (req, res) => {
    const { username, password, permissions } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    const data = getData();
    if (data.users.find(u => u.username === username))
        return res.status(409).json({ error: 'Username already exists' });

    data.users.push({
        id: Date.now(),
        username: sanitizeString(username, 100),
        password: hashPassword(password),
        role: 'user',
        permissions: permissions || {},
    });
    logAudit(data, 'CREATE_USER', req.session.user.username, sanitizeString(username, 100));
    saveData(data);
    res.json({ success: true });
});

// ── Change password (fix #3) ──────────────────────────────────────────────────
app.post('/api/change-password', requireAuth, (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword)
        return res.status(400).json({ error: 'Both current and new password required' });
    if (newPassword.length < 6)
        return res.status(400).json({ error: 'New password must be at least 6 characters' });

    const data = getData();
    const idx = data.users.findIndex(u => u.id === req.session.user.id);
    if (idx === -1) return res.status(404).json({ error: 'User not found' });

    if (!verifyPassword(currentPassword, data.users[idx].password))
        return res.status(401).json({ error: 'Current password is incorrect' });

    data.users[idx].password = hashPassword(newPassword);
    saveData(data);
    res.json({ success: true });
});

// FIX #3 — Users can change their own password
app.post('/api/delete-user', requireAdmin, (req, res) => {
    const data = getData();
    const target = data.users.find(u => u.id === req.body.id);
    if (!target) return res.status(404).json({ error: 'User not found' });
    if (target.role === 'superadmin') return res.status(403).json({ error: 'Cannot delete superadmin' });
    deletedUserIds.add(req.body.id);
    logAudit(data, 'DELETE_USER', req.session.user.username, target.username);
    data.users = data.users.filter(u => u.id !== req.body.id);
    saveData(data);
    res.json({ success: true });
});

// ── Settings ───────────────────────────────────────────────────────────────
app.post('/api/save-settings', requireAdmin, (req, res) => {
    const email = sanitizeString(req.body.email || '', 200);
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
        return res.status(400).json({ error: 'Invalid email address' });
    const data = getData();
    data.adminEmail = email;
    saveData(data);
    res.json({ success: true });
});

app.post('/api/clear-data', requireAdmin, (req, res) => {
    const { target } = req.body;
    const data = getData();
    if (target === 'history') { data.restockHistory = []; data.withdrawalHistory = []; }
    else if (target === 'registry') { data.stock = []; }
    else return res.status(400).json({ error: 'Invalid target' });
    saveData(data);
    res.json({ success: true });
});

// ── Data reads ─────────────────────────────────────────────────────────────
app.get('/api/all', (req, res) => {
    const data = getData();
    res.json({
        ...data,
        users: data.users.map(({ password: _, ...safe }) => safe),
    });
});

app.get('/api/users', (req, res) => {
    const users = getData().users.map(({ password: _, ...safe }) => safe);
    res.json(users);
});

app.get('/api/audit-log', requireAdmin, (req, res) => {
    res.json((getData().auditLog || []).slice().reverse());
});

app.post('/api/update-permissions', requireAdmin, (req, res) => {
    const { id, permissions } = req.body;
    const data = getData();
    const idx = data.users.findIndex(u => u.id === id);
    if (idx === -1) return res.status(404).json({ error: 'User not found' });
    if (data.users[idx].role === 'superadmin') return res.status(403).json({ error: 'Cannot modify superadmin' });
    data.users[idx].permissions = permissions;
    logAudit(data, 'EDIT_PERMISSIONS', req.session.user.username, data.users[idx].username);
    saveData(data);
    res.json({ success: true });
});

app.post('/api/set-quantity', requireAdmin, (req, res) => {
    const { id, quantity, reason } = req.body;
    const data = getData();
    const idx = data.stock.findIndex(s => s.id == id);
    if (idx === -1) return res.status(404).json({ error: 'Item not found' });
    const oldQty = data.stock[idx].quantity;
    const newQty = Math.max(0, parseInt(quantity) || 0);
    data.stock[idx].quantity = newQty;
    const diff = newQty - oldQty;
    const histEntry = {
        dateTime: new Date().toLocaleString(),
        name: data.stock[idx].name,
        partNumber: data.stock[idx].partNumber,
        qty: Math.abs(diff),
        performedBy: req.session.user.username,
        adjustedTo: newQty,
        reason: sanitizeString(reason || 'Manual adjustment', 200)
    };
    if (diff >= 0) data.restockHistory.push(histEntry);
    else data.withdrawalHistory.push(histEntry);
    logAudit(data, 'SET_QUANTITY', req.session.user.username, `${data.stock[idx].name}: ${oldQty} → ${newQty}`);
    saveData(data);
    res.json({ success: true });
});

app.post('/api/save-mail-settings', requireAdmin, (req, res) => {
    const mailUser = sanitizeString(req.body.mailUser || '', 200);
    const mailPass = req.body.mailPass || '';
    if (!mailUser) return res.status(400).json({ error: 'Email required' });
    const envLines = require('fs').existsSync(ENV_FILE)
        ? require('fs').readFileSync(ENV_FILE, 'utf8').split('\n').filter(l => l.trim()) : [];
    const kept = envLines.filter(l => !l.startsWith('MAIL_USER=') && !l.startsWith('MAIL_PASS='));
    kept.push(`MAIL_USER=${mailUser}`);
    if (mailPass) kept.push(`MAIL_PASS=${mailPass}`);
    require('fs').writeFileSync(ENV_FILE, kept.join('\n') + '\n');
    logAudit(getData(), 'SAVE_MAIL', req.session.user.username, mailUser);
    res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────────────────
//  DOCUMENTS / FILE UPLOAD
// ─────────────────────────────────────────────────────────────────────────────

const ALLOWED_EXT = new Set([
    'pdf',
    'csv', 'xls', 'xlsx', 'xlsm', 'xlsb',
    'doc', 'docx',
    'ppt', 'pptx',
    'png', 'jpg', 'jpeg', 'gif', 'webp',
    'txt', 'zip',
]);

const EXT_TO_MIME = {
    pdf: 'application/pdf',
    csv: 'text/csv',
    xls: 'application/vnd.ms-excel',
    xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    xlsm: 'application/vnd.ms-excel.sheet.macroEnabled.12',
    xlsb: 'application/vnd.ms-excel.sheet.binary.macroEnabled.12',
    doc: 'application/msword',
    docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    ppt: 'application/vnd.ms-powerpoint',
    pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg',
    gif: 'image/gif', webp: 'image/webp',
    txt: 'text/plain', zip: 'application/zip',
};

const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50 MB per file

// ── Zero-dependency multipart parser (binary-safe) ───────────────────────────
// Uses Buffer operations throughout — never converts to string before finding
// the boundary, which is what caused the old parser to corrupt binary files
// like xlsx/docx (their raw bytes could coincidentally match boundary chars).
function parseMultipart(req) {
    return new Promise((resolve, reject) => {
        const ct = req.headers['content-type'] || '';
        const bm = ct.match(/boundary=(?:"([^"]+)"|([^;\s]+))/i);
        if (!bm) return reject(new Error('Missing boundary in Content-Type'));
        const boundary = bm[1] || bm[2];

        const chunks = [];
        let total = 0;
        req.on('error', reject);
        req.on('data', chunk => {
            total += chunk.length;
            if (total > 100 * 1024 * 1024) { req.destroy(); return reject(new Error('Upload too large')); }
            chunks.push(chunk);
        });
        req.on('end', () => {
            try { resolve(splitMultipart(Buffer.concat(chunks), boundary)); }
            catch (e) { reject(e); }
        });
    });
}

function indexOf(haystack, needle, start) {
    // Binary-safe Boyer-Moore-Horspool search
    const hLen = haystack.length, nLen = needle.length;
    if (nLen === 0) return start;
    const skip = new Uint32Array(256).fill(nLen);
    for (let i = 0; i < nLen - 1; i++) skip[needle[i]] = nLen - 1 - i;
    let i = start + nLen - 1;
    while (i < hLen) {
        let j = nLen - 1, k = i;
        while (j >= 0 && haystack[k] === needle[j]) { j--; k--; }
        if (j < 0) return k + 1;
        i += skip[haystack[i]];
    }
    return -1;
}

function splitMultipart(body, boundary) {
    const files = [];
    const fields = {};
    const DASH2 = Buffer.from('--');
    const CRLF = Buffer.from('\r\n');
    const CRLFCRLF = Buffer.from('\r\n\r\n');
    const delim = Buffer.concat([CRLF, DASH2, Buffer.from(boundary)]);
    const start = Buffer.concat([DASH2, Buffer.from(boundary)]);

    let pos = indexOf(body, start, 0);
    if (pos === -1) return { files, fields };
    pos += start.length;

    while (pos < body.length) {
        // After boundary: '--' means end, '\r\n' means next part
        if (body[pos] === 0x2d && body[pos + 1] === 0x2d) break;
        if (body[pos] === 0x0d && body[pos + 1] === 0x0a) pos += 2; else break;

        const partEnd = indexOf(body, delim, pos);
        if (partEnd === -1) break;

        const part = body.slice(pos, partEnd);
        pos = partEnd + delim.length;

        const hEnd = indexOf(part, CRLFCRLF, 0);
        if (hEnd === -1) continue;

        const headerStr = part.slice(0, hEnd).toString('binary'); // latin-1 safe
        const data = part.slice(hEnd + 4);                   // raw bytes

        const nameM = headerStr.match(/Content-Disposition:[^\r\n]*name="([^"]+)"/i);
        const fileM = headerStr.match(/Content-Disposition:[^\r\n]*filename="([^"]*)"/i);
        if (!nameM) continue;

        if (fileM) {
            files.push({ fieldName: nameM[1], originalName: fileM[1] || 'upload', data });
        } else {
            fields[nameM[1]] = data.toString('utf8');
        }
    }
    return { files, fields };
}

function getDocs() {
    const data = getData();
    return data.documents || [];
}

function saveDocs(docs) {
    const data = getData();
    data.documents = docs;
    saveData(data);
}

app.post('/api/documents/upload', requireAuth, requireAdmin, async (req, res) => {
    let parsed;
    try {
        parsed = await parseMultipart(req);
    } catch (e) {
        return res.status(400).json({ error: 'Upload parse error: ' + e.message });
    }

    if (!parsed.files.length) {
        return res.status(400).json({ error: 'No files received.' });
    }

    const docs = getDocs();
    const saved = [];
    const errors = [];

    for (const file of parsed.files) {
        if (!file.originalName) continue;
        const extRaw = path.extname(file.originalName).replace('.', '').toLowerCase();

        if (!ALLOWED_EXT.has(extRaw)) {
            errors.push(`${file.originalName}: file type .${extRaw} is not allowed`);
            continue;
        }
        if (file.data.length === 0) {
            errors.push(`${file.originalName}: empty file`);
            continue;
        }
        if (file.data.length > MAX_FILE_SIZE) {
            errors.push(`${file.originalName}: exceeds 50 MB limit`);
            continue;
        }

        const canonicalMime = EXT_TO_MIME[extRaw] || 'application/octet-stream';
        const storedName = `${Date.now()}_${crypto.randomBytes(8).toString('hex')}.${extRaw}`;
        const filePath = path.join(UPLOADS_DIR, storedName);

        fs.writeFileSync(filePath, file.data); // Buffer written directly — binary-safe

        const meta = {
            id: Date.now() + Math.random(),
            originalName: file.originalName,
            storedName,
            size: file.data.length,
            mimeType: canonicalMime,
            uploadedBy: req.session.user.username,
            uploadedAt: new Date().toISOString(),
            category: sanitizeString(parsed.fields.category || '', 50),
        };
        docs.push(meta);
        saved.push(meta);
    }

    saveDocs(docs);
    res.json({ success: true, saved, errors });
});

app.get('/api/documents', requireAuth, (req, res) => {
    res.json(getDocs());
});

app.get('/api/documents/:id', requireAuth, (req, res) => {
    const doc = getDocs().find(d => String(d.id) === req.params.id);
    if (!doc) return res.status(404).json({ error: 'Document not found' });

    const filePath = path.join(UPLOADS_DIR, doc.storedName);
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File missing on disk' });

    res.setHeader('Content-Type', doc.mimeType);
    res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(doc.originalName)}"`);
    fs.createReadStream(filePath).pipe(res);
});

app.delete('/api/documents/:id', requireAuth, requireAdmin, (req, res) => {
    const docs = getDocs();
    const index = docs.findIndex(d => String(d.id) === req.params.id);
    if (index === -1) return res.status(404).json({ error: 'Document not found' });

    const [doc] = docs.splice(index, 1);
    const filePath = path.join(UPLOADS_DIR, doc.storedName);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

    saveDocs(docs);
    res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));