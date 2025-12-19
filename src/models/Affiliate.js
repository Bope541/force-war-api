const mongoose = require('mongoose');

// Sub-schema para detalhes de pagamento
const PaymentDetailsSchema = new mongoose.Schema({
    accountHolderName: { type: String, required: true },
    pixKeyType: {
        type: String,
        required: true,
        enum: ['cpf_cnpj', 'telefone', 'email', 'aleatoria']
    },
    pixKey: { type: String, required: true }
}, { _id: false });

// (ATUALIZADO) Sub-schema para pedidos de saque
const WithdrawalRequestSchema = new mongoose.Schema({
    amount: { // Em centavos
        type: Number,
        required: true
    },
    status: {
        type: String,
        // pending = Solicitado
        // approved = Aprovado (Aguardando Pagamento)
        // completed = Pago (Pagamento Realizado)
        // rejected = Recusado (Pagamento Cancelado/Recusado)
        enum: ['pending', 'approved', 'completed', 'rejected'],
        default: 'pending'
    },
    paymentDetailsSnapshot: { 
        type: PaymentDetailsSchema,
        required: true
    },
    rejectionReason: { // Caso o admin recuse
        type: String,
        default: null
    }
}, { timestamps: true });

const AffiliateSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        unique: true
    },
    fullName: {
        type: String,
        required: true
    },
    discordId: {
        type: String
    },
    paymentDetails: {
        type: PaymentDetailsSchema,
        required: true
    },
    socials: {
        twitter: String,
        youtube: String,
        twitch: String
    },
    commissionRate: {
        type: Number,
        default: 25
    },
    linkedCoupons: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Coupon'
    }],
    status: {
        type: String,
        enum: ['active', 'inactive', 'banned'],
        default: 'active'
    },
    
    // --- Valores Financeiros (em centavos) ---
    balance: { type: Number, default: 0 },
    totalEarned: { type: Number, default: 0 },
    totalWithdrawn: { type: Number, default: 0 },

    // Histórico de Saques
    withdrawals: [WithdrawalRequestSchema]

}, { timestamps: true });

module.exports = mongoose.model('Affiliate', AffiliateSchema);