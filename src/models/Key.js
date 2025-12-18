const mongoose = require('mongoose');

const KeySchema = new mongoose.Schema({
    // A key em si (ex: INVICT-FIVE M-MONTHLY-XYZ123)
    keyString: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        uppercase: true
    },
    productName: {
        type: String,
        required: true
    },
    planName: {
        type: String,
        required: true
    },
    // Duração em dias. -1 significa "Vitalício".
    durationInDays: {
        type: Number,
        required: true 
    },
    isRedeemed: {
        type: Boolean,
        default: false
    },
    redeemedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
    },
    redeemedAt: {
        type: Date,
        default: null
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('Key', KeySchema);