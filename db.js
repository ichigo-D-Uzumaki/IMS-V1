const mongoose = require('mongoose');

// ── Schema ────────────────────────────────────────────────────────────────────
// We store everything as a single "singleton" document — mirrors data.json shape.
// Mixed type gives us the same flexibility as a plain JSON file.
const appDataSchema = new mongoose.Schema(
    {
        _id:                { type: String, default: 'singleton' },
        users:              { type: mongoose.Schema.Types.Mixed, default: [] },
        stock:              { type: mongoose.Schema.Types.Mixed, default: [] },
        restockHistory:     { type: mongoose.Schema.Types.Mixed, default: [] },
        withdrawalHistory:  { type: mongoose.Schema.Types.Mixed, default: [] },
        adminEmail:         { type: String, default: '' },
        auditLog:           { type: mongoose.Schema.Types.Mixed, default: [] },
        documents:          { type: mongoose.Schema.Types.Mixed, default: [] },
        mailSettings:       { type: mongoose.Schema.Types.Mixed, default: {} },
    },
    { _id: false, strict: false }
);

const AppData = mongoose.model('AppData', appDataSchema);

// ── Connection ─────────────────────────────────────────────────────────────────
async function connectDB() {
    const uri = process.env.MONGODB_URI;
    if (!uri) throw new Error('MONGODB_URI environment variable is not set.');

    await mongoose.connect(uri, {
        serverSelectionTimeoutMS: 10000,
    });
    console.log('✅ Connected to MongoDB');
}

// ── Helpers ────────────────────────────────────────────────────────────────────
const EMPTY_DB = () => ({
    _id: 'singleton',
    users: [],
    stock: [],
    restockHistory: [],
    withdrawalHistory: [],
    adminEmail: '',
    auditLog: [],
    documents: [],
    mailSettings: {},
});

async function getAppData() {
    let doc = await AppData.findById('singleton').lean();
    if (!doc) {
        doc = EMPTY_DB();
        await AppData.create(doc);
    }
    return doc;
}

async function saveAppData(data) {
    // Use replace-style upsert so all fields (including removals) are honoured
    await AppData.replaceOne({ _id: 'singleton' }, data, { upsert: true });
}

module.exports = { connectDB, getAppData, saveAppData };
