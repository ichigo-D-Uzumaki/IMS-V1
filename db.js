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
let isConnected = false;

async function connectDB() {
    if (isConnected) return;

    const uri = process.env.MONGO_URI || process.env.MONGODB_URI;
    if (!uri) {
        throw new Error('MONGO_URI or MONGODB_URI environment variable is required for production.');
    }

    try {
        await mongoose.connect(uri, {
            serverSelectionTimeoutMS: 10000,
            socketTimeoutMS: 45000,
            maxPoolSize: 10,
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
        });
        isConnected = true;
        console.log('✅ Connected to MongoDB Atlas');
    } catch (error) {
        console.error('❌ MongoDB connection error:', error.message);
        throw error;
    }
}

// Handle connection events
mongoose.connection.on('error', (err) => {
    console.error('MongoDB connection error:', err);
    isConnected = false;
});

mongoose.connection.on('disconnected', () => {
    console.log('MongoDB disconnected');
    isConnected = false;
});

mongoose.connection.on('reconnected', () => {
    console.log('MongoDB reconnected');
    isConnected = true;
});

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
    try {
        await connectDB();
        let doc = await AppData.findById('singleton').lean();
        if (!doc) {
            doc = EMPTY_DB();
            await AppData.create(doc);
        }
        return doc;
    } catch (error) {
        console.error('Error getting app data:', error);
        throw error;
    }
}

async function saveAppData(data) {
    try {
        await connectDB();
        // Use replace-style upsert so all fields (including removals) are honoured
        await AppData.replaceOne({ _id: 'singleton' }, data, { upsert: true });
    } catch (error) {
        console.error('Error saving app data:', error);
        throw error;
    }
}

module.exports = { connectDB, getAppData, saveAppData };
