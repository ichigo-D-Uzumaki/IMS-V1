require('dotenv').config();
const mongoose = require('mongoose');
const fs = require('fs');

async function seed() {
    const mongoUri = process.env.MONGO_URI;
    if (!mongoUri) {
        console.error('MONGO_URI environment variable is required');
        process.exit(1);
    }

    try {
        await mongoose.connect(mongoUri);
        console.log('Connected to MongoDB Atlas');

        const data = JSON.parse(fs.readFileSync('data.json', 'utf8'));

        // Clear and seed users
        await mongoose.connection.collection('users').deleteMany({});
        if (data.users && data.users.length > 0) {
            await mongoose.connection.collection('users').insertMany(data.users);
            console.log(`Seeded ${data.users.length} users`);
        }

        // Clear and seed stock
        await mongoose.connection.collection('stock').deleteMany({});
        if (data.stock && data.stock.length > 0) {
            await mongoose.connection.collection('stock').insertMany(data.stock);
            console.log(`Seeded ${data.stock.length} stock items`);
        }

        // Clear and seed history (combine restock and withdrawal)
        await mongoose.connection.collection('history').deleteMany({});
        const history = (data.restockHistory || []).concat(data.withdrawalHistory || []);
        if (history.length > 0) {
            await mongoose.connection.collection('history').insertMany(history);
            console.log(`Seeded ${history.length} history records`);
        }

        // Clear and seed documents
        await mongoose.connection.collection('documents').deleteMany({});
        if (data.documents && data.documents.length > 0) {
            await mongoose.connection.collection('documents').insertMany(data.documents);
            console.log(`Seeded ${data.documents.length} documents`);
        }

        // Clear and seed settings
        await mongoose.connection.collection('settings').deleteMany({});
        const settings = { adminEmail: data.adminEmail || '' };
        await mongoose.connection.collection('settings').insertOne(settings);
        console.log('Seeded settings');

        console.log('✅ Data seeding completed successfully');

    } catch (error) {
        console.error('Error seeding data:', error);
        process.exit(1);
    } finally {
        await mongoose.connection.close();
        console.log('Database connection closed');
    }
}

seed();