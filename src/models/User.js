const mongoose = require('mongoose');

// (NOVO) Sub-schema para assinaturas ativas
const SubscriptionSchema = new mongoose.Schema({
    productName: {
        type: String,
        required: true
    },
    planName: {
        type: String,
        required: true
    },
    redeemedAt: {
        type: Date,
        default: Date.now
    },
    expiresAt: {
        type: Date, // Se for nulo ou uma data muito no futuro, é vitalício
        default: null
    },
    keyUsed: { // Guarda a key que ativou esta assinatura
        type: String,
        required: true
    }
});

const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true, 
        match: [/.+@.+\..+/, 'Por favor, insira um email válido']
    },
    password: {
        type: String,
        required: false 
    },
    provider: {
        type: String,
        required: true,
        default: 'local'
    },
    discordId: {
        type: String,
    },
    avatar: {
        type: String
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    // --- Campos de Reset de Senha ---
    resetPasswordCode: {
        type: String
    },
    resetPasswordExpires: {
        type: Date
    },
    // --- Campo de Cargo ---
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    },
    
    // --- (NOVO) Campo de Assinaturas Ativas ---
    activeSubscriptions: [SubscriptionSchema]
});

UserSchema.index({ discordId: 1 }, { unique: true, sparse: true });

module.exports = mongoose.model('User', UserSchema);