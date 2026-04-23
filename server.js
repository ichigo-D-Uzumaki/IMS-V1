require('dotenv').config(); // Load .env for local development

const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const nodemailer = require('nodemailer');
const helmet = require('helmet');
const compression = require('compression');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { connectDB, getAppData, saveAppData } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';
const MONGO_URI = process.env.MONGO_URI || process.env.MONGODB_URI;

// ── Security & Performance Middlewares ──────────────────────────────────────────
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdn.jsdelivr.net"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            scriptSrc: ["'self'", "https://cdnjs.cloudflare.com", "https://cdn.sheetjs.com", "https://cdn.jsdelivr.net"],
            imgSrc: ["'self'", "data:", "https:", "http:"],
            connectSrc: ["'self'", "https:"],
        },
    },
}));
app.use(compression());
app.use(cors({
    origin: IS_PROD ? process.env.FRONTEND_URL || 'https://your-frontend-domain.vercel.app' : 'http://localhost:3000',
    credentials: true,
}));

// Global rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
});
app.use(limiter);

// Local-only paths (ignored in production with Mongo)
const DATA_FILE = 'data.json';
const ENV_FILE = '.env';
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const BACKUP_DIR = path.join(__dirname, 'backups');

// ── Cloudinary (optional — required for file uploads on cloud) ─────────────────
let cloudinaryV2 = null;
const USE_CLOUDINARY = !!(
    process.env.CLOUDINARY_CLOUD_NAME &&
    process.env.CLOUDINARY_API_KEY &&
    process.env.CLOUDINARY_API_SECRET
);
if (USE_CLOUDINARY) {
    cloudinaryV2 = require('cloudinary').v2;
    cloudinaryV2.config({
        cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
        api_key: process.env.CLOUDINARY_API_KEY,
        api_secret: process.env.CLOUDINARY_API_SECRET,
    });
    console.log('✅  Cloudinary configured for file uploads.');
}

// Ensure local directories exist (skipped when running fully on cloud)
if (!IS_PROD || !MONGO_URI) {
    if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
    if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
}

// ─────────────────────────────────────────────────────────────────────────────
//  ENCRYPTION SETUP  (AES-256-GCM — authenticated encryption)
//  Key source : DTVS_SECRET env var (required in production)
//               Auto-generated & saved to .env in local dev
// ─────────────────────────────────────────────────────────────────────────────
const ALGO = 'aes-256-gcm';
const IV_LEN = 12; // 96-bit IV recommended for GCM

function loadOrCreateKey() {
    let dataKey = process.env.DTVS_SECRET;
    let sessionSecret = process.env.SESSION_SECRET;

    if (!IS_PROD) {
        // Local dev: read from .env file and auto-generate if missing
        let lines = [];
        if (fs.existsSync(ENV_FILE)) {
            lines = fs.readFileSync(ENV_FILE, 'utf8').split('\n');
        }
        if (!dataKey) {
            const keyLine = lines.find(l => l.startsWith('DTVS_SECRET='));
            dataKey = keyLine ? keyLine.split('=')[1].trim() : null;
        }
        if (!sessionSecret) {
            const sessionLine = lines.find(l => l.startsWith('SESSION_SECRET='));
            sessionSecret = sessionLine ? sessionLine.split('=')[1].trim() : null;
        }

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
            try {
                const kept = lines.filter(l =>
                    !l.startsWith('DTVS_SECRET=') && !l.startsWith('SESSION_SECRET=') && l.trim()
                );
                kept.push(`DTVS_SECRET=${dataKey}`, `SESSION_SECRET=${sessionSecret}`);
                fs.writeFileSync(ENV_FILE, kept.join('\n') + '\n');
                console.log('✅  Secrets saved to .env');
            } catch (e) {
                console.warn('⚠️  Could not write secrets to .env:', e.message);
            }
        }
    }

    // Both local and production: validate secrets before starting
    if (!dataKey || dataKey.length !== 64) {
        throw new Error('DTVS_SECRET must be a 64-character hex string set as an environment variable.');
    }
    if (!sessionSecret || sessionSecret.length < 64) {
        throw new Error('SESSION_SECRET must be ≥64 characters and set as an environment variable.');
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
//  DATA LAYER  (async — MongoDB when MONGO_URI is set, else local data.json)
// ─────────────────────────────────────────────────────────────────────────────
const EMPTY_DB = () => ({
    users: [], stock: [], restockHistory: [], withdrawalHistory: [],
    adminEmail: '', auditLog: [], documents: [], mailSettings: {},
});

function logAudit(data, action, performedBy, detail = '') {
    if (!data.auditLog) data.auditLog = [];
    data.auditLog.push({ ts: new Date().toISOString(), action, performedBy, detail });
    if (data.auditLog.length > 500) data.auditLog = data.auditLog.slice(-500); // keep last 500
}

let _dbCache = null; // in-memory cache; null = not loaded yet

async function getData() {
    if (_dbCache) return _dbCache; // serve from cache

    let raw;
    if (MONGO_URI) {
        raw = await getAppData();
    } else {
        if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, JSON.stringify(EMPTY_DB(), null, 2));
        raw = JSON.parse(fs.readFileSync(DATA_FILE));
    }

    _dbCache = {
        ...EMPTY_DB(),
        ...raw,
        stock:              (raw.stock              || []).map(decryptStock),
        restockHistory:     (raw.restockHistory     || []).map(decryptHistory),
        withdrawalHistory:  (raw.withdrawalHistory  || []).map(decryptHistory),
    };
    return _dbCache;
}

async function saveData(data) {
    _dbCache = data; // update cache first

    const toWrite = {
        ...data,
        stock:              (data.stock              || []).map(encryptStock),
        restockHistory:     (data.restockHistory     || []).map(encryptHistory),
        withdrawalHistory:  (data.withdrawalHistory  || []).map(encryptHistory),
    };

    if (MONGO_URI) {
        await saveAppData(toWrite);
    } else {
        // Rolling backup — keep last 5 versions (local dev only)
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
        fs.writeFileSync(DATA_FILE, JSON.stringify(toWrite, null, 2));
    }
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
app.use(express.static(__dirname));
app.use(session({
    secret: SESSION_SECRET,
    store: MONGO_URI ? MongoStore.create({
        mongoUrl: MONGO_URI,
        collectionName: 'sessions',
        ttl: 24 * 60 * 60, // 1 day
    }) : undefined, // memory store for local dev
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 8 * 60 * 60 * 1000,
        secure: IS_PROD, // HTTPS-only cookies in production
    }
}));

const deletedUserIds = new Set(); // active sessions of deleted users are rejected

// ─────────────────────────────────────────────────────────────────────────────
//  AUTH MIDDLEWARE
// ─────────────────────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
    if (!req.session || !req.session.user) {
        return res.status(401).json({ error: 'Authentication required' });
    }
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
//  Priority: process.env → DB mailSettings → .env file (local dev only)
// ─────────────────────────────────────────────────────────────────────────────
async function getMailCredentials() {
    // 1. Environment variables (cloud dashboard or local .env via dotenv)
    if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
        return { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS };
    }
    // 2. DB mailSettings (saved via admin UI — works on both Mongo and local)
    try {
        const data = await getData();
        const ms = data.mailSettings || {};
        if (ms.mailUser && ms.mailPass) return { user: ms.mailUser, pass: ms.mailPass };
    } catch (_) { /* ignore */ }
    // 3. .env file fallback (local dev only)
    if (!IS_PROD && fs.existsSync(ENV_FILE)) {
        const envLines = fs.readFileSync(ENV_FILE, 'utf8').split('\n');
        const get = key => {
            const l = envLines.find(line => line.startsWith(key + '='));
            return l ? l.split('='').slice(1).join('=').trim() : '';
        };
        return { user: get('EMAIL_USER'), pass: get('EMAIL_PASS') };
    }
    return { user: '', pass: '' };
}

async function createTransporter() {
    const { user, pass } = await getMailCredentials();
    if (!user || !pass) {
        console.warn('⚠️  MAIL_USER / MAIL_PASS not set — email sending disabled.');
        return null;
    }
    return nodemailer.createTransport({ service: 'gmail', auth: { user, pass } });
}

async function sendMail(subject, html) {
    const transporter = await createTransporter();
    if (!transporter) return;
    const data = await getData();
    if (!data.adminEmail) { console.warn('No admin email configured.'); return; }
    const { user } = await getMailCredentials();
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
app.post('/api/login', async (req, res) => {
    const ip = req.ip || req.socket.remoteAddress;
    if (!checkRateLimit(ip)) {
        return res.status(429).json({ error: 'Too many login attempts. Try again in 15 minutes.' });
    }

    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });

    const data = await getData();
    const user = data.users.find(u => u.username === username);

    if (!user || !verifyPassword(password, user.password)) {
        return res.status(401).json({ error: 'Invalid username or password' });
    }

    if (!user.password.startsWith('pbkdf2:')) {
        const idx = data.users.findIndex(u => u.username === username);
        data.users[idx].password = hashPassword(password);
        await saveData(data);
    }

    resetRateLimit(ip);

    req.session.regenerate(err => {
        if (err) return res.status(500).json({ error: 'Session error' });
        const safeUser = { id: user.id, username: user.username, role: user.role, permissions: user.permissions };
        req.session.user = safeUser;
        // Remember Me: extend cookie to 30 days if requested
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
app.post('/api/add-item', requireAdmin, async (req, res) => {
    const data = await getData();
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
        rack: sanitizeString(req.body.rack || '', 100),
    };
    if (!newItem.name) return res.status(400).json({ error: 'Name is required' });
    data.stock.push(newItem);
    logAudit(data, 'ADD_ITEM', req.session.user.username, `${newItem.name} (${newItem.partNumber})`);
    await saveData(data);
    res.json({ success: true, item: newItem });
});

// ── Bulk add items (used by XLS import — single round-trip) ──────────────────
app.post('/api/bulk-add-items', requireAdmin, async (req, res) => {
    const { items } = req.body;
    if (!Array.isArray(items) || items.length === 0)
        return res.status(400).json({ error: 'No items provided' });

    const data = await getData();
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
    await saveData(data);
    res.json({ success: true, added: added.length, skipped: skipped.length, failed: failed.length });
});

app.post('/api/update-stock', async (req, res) => {
    const { id, amount, type, details } = req.body;
    const data = await getData();
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

    await saveData(data);
    res.json({ success: true });
});

app.post('/api/send-pr', async (req, res) => {
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

    try {
        await sendMail(
            `📝 Bulk PR Request - ${items.length} Items`,
            `<h3>Manual Purchase Request</h3>
             <table border="1" cellpadding="8" style="border-collapse:collapse;width:100%;">
                 <thead style="background-color:#333;color:#fff;">
                     <tr><th>#</th><th>Name</th><th>Part Number</th><th>Qty</th><th>Price</th></tr>
                 </thead>
                 <tbody>${tableRows}</tbody>
             </table>`
        );
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Mail error' });
    }
});

app.post('/api/edit-item', requireAdmin, async (req, res) => {
    const { id, updatedItem } = req.body;
    const data = await getData();
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
        rack: sanitizeString(updatedItem.rack || '', 100),
    };
    logAudit(data, 'EDIT_ITEM', req.session.user.username, `id=${id}`);
    await saveData(data);
    res.json({ success: true });
});

// ── Inline rack update endpoint (used by Update & BOM tabs) ──────────────────
app.post('/api/update-rack', requireAuth, async (req, res) => {
    const { id, rack } = req.body;
    const data = await getData();
    const index = data.stock.findIndex(s => s.id == id);
    if (index === -1) return res.status(404).json({ error: 'Item not found' });
    data.stock[index].rack = sanitizeString(rack || '', 100);
    await saveData(data);
    res.json({ success: true });
});

app.post('/api/delete-item', requireAdmin, async (req, res) => {
    const data = await getData();
    const before = data.stock.length;
    const toDelete = data.stock.find(s => s.id == req.body.id);
    data.stock = data.stock.filter(s => s.id != req.body.id);
    if (data.stock.length === before) return res.status(404).json({ error: 'Item not found' });
    logAudit(data, 'DELETE_ITEM', req.session.user.username, toDelete ? `${toDelete.name}` : `id=${req.body.id}`);
    await saveData(data);
    res.json({ success: true });
});

// ── Users ──────────────────────────────────────────────────────────────────
app.post('/api/create-user', requireAdmin, async (req, res) => {
    const { username, password, permissions } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    const data = await getData();
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
    await saveData(data);
    res.json({ success: true });
});

// ── Change password ───────────────────────────────────────────────────────────
app.post('/api/change-password', requireAuth, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword)
        return res.status(400).json({ error: 'Both current and new password required' });
    if (newPassword.length < 6)
        return res.status(400).json({ error: 'New password must be at least 6 characters' });

    const data = await getData();
    const idx = data.users.findIndex(u => u.id === req.session.user.id);
    if (idx === -1) return res.status(404).json({ error: 'User not found' });

    if (!verifyPassword(currentPassword, data.users[idx].password))
        return res.status(401).json({ error: 'Current password is incorrect' });

    data.users[idx].password = hashPassword(newPassword);
    await saveData(data);
    res.json({ success: true });
});

app.post('/api/delete-user', requireAdmin, async (req, res) => {
    const data = await getData();
    const target = data.users.find(u => u.id === req.body.id);
    if (!target) return res.status(404).json({ error: 'User not found' });
    if (target.role === 'superadmin') return res.status(403).json({ error: 'Cannot delete superadmin' });
    deletedUserIds.add(req.body.id);
    logAudit(data, 'DELETE_USER', req.session.user.username, target.username);
    data.users = data.users.filter(u => u.id !== req.body.id);
    await saveData(data);
    res.json({ success: true });
});

// ── Settings ───────────────────────────────────────────────────────────────
app.post('/api/save-settings', requireAdmin, async (req, res) => {
    const email = sanitizeString(req.body.email || '', 200);
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
        return res.status(400).json({ error: 'Invalid email address' });
    const data = await getData();
    data.adminEmail = email;
    await saveData(data);
    res.json({ success: true });
});

app.post('/api/clear-data', requireAdmin, async (req, res) => {
    const { target } = req.body;
    const data = await getData();
    if (target === 'history') { data.restockHistory = []; data.withdrawalHistory = []; }
    else if (target === 'registry') { data.stock = []; }
    else return res.status(400).json({ error: 'Invalid target' });
    await saveData(data);
    res.json({ success: true });
});

// ── Data reads ─────────────────────────────────────────────────────────────
app.get('/api/all', async (req, res) => {
    const data = await getData();
    res.json({
        ...data,
        users: data.users.map(({ password: _, ...safe }) => safe),
    });
});

app.get('/api/users', async (req, res) => {
    const users = (await getData()).users.map(({ password: _, ...safe }) => safe);
    res.json(users);
});

app.get('/api/audit-log', requireAdmin, async (req, res) => {
    res.json(((await getData()).auditLog || []).slice().reverse());
});

app.post('/api/update-permissions', requireAdmin, async (req, res) => {
    const { id, permissions } = req.body;
    const data = await getData();
    const idx = data.users.findIndex(u => u.id === id);
    if (idx === -1) return res.status(404).json({ error: 'User not found' });
    if (data.users[idx].role === 'superadmin') return res.status(403).json({ error: 'Cannot modify superadmin' });
    data.users[idx].permissions = permissions;
    logAudit(data, 'EDIT_PERMISSIONS', req.session.user.username, data.users[idx].username);
    await saveData(data);
    res.json({ success: true });
});

app.post('/api/set-quantity', requireAdmin, async (req, res) => {
    const { id, quantity, reason } = req.body;
    const data = await getData();
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
    await saveData(data);
    res.json({ success: true });
});

app.post('/api/save-mail-settings', requireAdmin, async (req, res) => {
    const mailUser = sanitizeString(req.body.mailUser || '', 200);
    const mailPass = req.body.mailPass || '';
    if (!mailUser) return res.status(400).json({ error: 'Email required' });

    const data = await getData();

    if (MONGO_URI) {
        // Cloud: persist mail credentials in the database
        if (!data.mailSettings) data.mailSettings = {};
        data.mailSettings.mailUser = mailUser;
        if (mailPass) data.mailSettings.mailPass = mailPass;
        logAudit(data, 'SAVE_MAIL', req.session.user.username, mailUser);
        await saveData(data);
    } else {
        // Local dev: write to .env file
        try {
            const envLines = fs.existsSync(ENV_FILE)
                ? fs.readFileSync(ENV_FILE, 'utf8').split('\n').filter(l => l.trim()) : [];
            const kept = envLines.filter(l => !l.startsWith('EMAIL_USER=') && !l.startsWith('EMAIL_PASS='));
            kept.push(`EMAIL_USER=${mailUser}`);
            if (mailPass) kept.push(`EMAIL_PASS=${mailPass}`);
            fs.writeFileSync(ENV_FILE, kept.join('\n') + '\n');
        } catch (e) {
            return res.status(500).json({ error: 'Could not save mail settings: ' + e.message });
        }
        logAudit(data, 'SAVE_MAIL', req.session.user.username, mailUser);
        await saveData(data);
    }
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

async function getDocs() {
    const data = await getData();
    return data.documents || [];
}

async function saveDocs(docs) {
    const data = await getData();
    data.documents = docs;
    await saveData(data);
}

app.post('/api/documents/upload', requireAuth, requireAdmin, async (req, res) => {
    // Cloud without Cloudinary configured → reject gracefully
    if (IS_PROD && !USE_CLOUDINARY) {
        return res.status(503).json({
            error: 'File uploads require Cloudinary configuration. Please set CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET environment variables.'
        });
    }

    let parsed;
    try {
        parsed = await parseMultipart(req);
    } catch (e) {
        return res.status(400).json({ error: 'Upload parse error: ' + e.message });
    }

    if (!parsed.files.length) {
        return res.status(400).json({ error: 'No files received.' });
    }

    const docs = await getDocs();
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
        let meta;

        if (USE_CLOUDINARY) {
            // ── Upload buffer to Cloudinary ────────────────────────────────
            try {
                const uploadResult = await new Promise((resolve, reject) => {
                    const stream = cloudinaryV2.uploader.upload_stream(
                        {
                            resource_type: 'raw',
                            public_id: `ims-uploads/${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
                            use_filename: false,
                        },
                        (error, result) => error ? reject(error) : resolve(result)
                    );
                    stream.end(file.data);
                });

                meta = {
                    id: Date.now() + Math.random(),
                    originalName: file.originalName,
                    storedName: uploadResult.public_id,
                    cloudinaryUrl: uploadResult.secure_url,
                    size: file.data.length,
                    mimeType: canonicalMime,
                    uploadedBy: req.session.user.username,
                    uploadedAt: new Date().toISOString(),
                    category: sanitizeString(parsed.fields.category || '', 50),
                };
            } catch (e) {
                errors.push(`${file.originalName}: Cloudinary upload failed — ${e.message}`);
                continue;
            }
        } else {
            // ── Save to local disk (dev only) ──────────────────────────────
            const storedName = `${Date.now()}_${crypto.randomBytes(8).toString('hex')}.${extRaw}`;
            const filePath = path.join(UPLOADS_DIR, storedName);
            fs.writeFileSync(filePath, file.data); // Buffer written directly — binary-safe

            meta = {
                id: Date.now() + Math.random(),
                originalName: file.originalName,
                storedName,
                size: file.data.length,
                mimeType: canonicalMime,
                uploadedBy: req.session.user.username,
                uploadedAt: new Date().toISOString(),
                category: sanitizeString(parsed.fields.category || '', 50),
            };
        }

        docs.push(meta);
        saved.push(meta);
    }

    await saveDocs(docs);
    res.json({ success: true, saved, errors });
});

app.get('/api/documents', requireAuth, async (req, res) => {
    res.json(await getDocs());
});

app.get('/api/documents/:id', requireAuth, async (req, res) => {
    const doc = (await getDocs()).find(d => String(d.id) === req.params.id);
    if (!doc) return res.status(404).json({ error: 'Document not found' });

    // Cloudinary-hosted file: redirect to the CDN URL
    if (doc.cloudinaryUrl) {
        return res.redirect(302, doc.cloudinaryUrl);
    }

    // Local file
    const filePath = path.join(UPLOADS_DIR, doc.storedName);
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File missing on disk' });

    res.setHeader('Content-Type', doc.mimeType);
    res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(doc.originalName)}"`);
    fs.createReadStream(filePath).pipe(res);
});

app.delete('/api/documents/:id', requireAuth, requireAdmin, async (req, res) => {
    const docs = await getDocs();
    const index = docs.findIndex(d => String(d.id) === req.params.id);
    if (index === -1) return res.status(404).json({ error: 'Document not found' });

    const [doc] = docs.splice(index, 1);

    if (doc.cloudinaryUrl && USE_CLOUDINARY) {
        // Remove from Cloudinary
        try {
            await cloudinaryV2.uploader.destroy(doc.storedName, { resource_type: 'raw' });
        } catch (e) {
            console.error('Cloudinary delete error:', e.message);
        }
    } else if (doc.storedName && !doc.cloudinaryUrl) {
        // Remove from local disk
        const filePath = path.join(UPLOADS_DIR, doc.storedName);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    }

    await saveDocs(docs);
    res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────────────────
//  ERROR HANDLING MIDDLEWARE
// ─────────────────────────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({ error: IS_PROD ? 'Internal server error' : err.message });
});

// ─────────────────────────────────────────────────────────────────────────────
//  START SERVER
// ─────────────────────────────────────────────────────────────────────────────
async function start() {
    if (MONGO_URI) {
        await connectDB();
    }
    app.listen(PORT, () => console.log(`✅ Server running at http://localhost:${PORT}`));
}

start().catch(err => {
    console.error('❌ Startup failed:', err.message);
    process.exit(1);
});