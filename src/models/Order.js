const mongoose = require('mongoose');

const OrderSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    productId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Product',
        required: true
    },
    orderNumber: {
        type: String,
        required: true,
        unique: true
    },
    productTitle: {
        type: String,
        required: true
    },
    productPlan: {
        type: String,
        required: true
    },
    
    // --- Campos de Valores ---
    subtotal: { // Preço original (em centavos)
        type: Number,
        required: true
    },
    couponApplied: { // Código do cupom (ex: "BEMVINDO10")
        type: String,
        default: null
    },
    discountAmount: { // Valor do desconto (em centavos)
        type: Number,
        default: 0
    },
    amount: { // Preço FINAL (subtotal - discountAmount) em centavos
        type: Number,
        required: true
    },
    
    // (NOVO) Registra qual afiliado ganhou com a venda
    commissionPaidTo: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Affiliate',
        default: null
    },

    status: {
        type: String,
        enum: ['pending', 'paid', 'cancelled'],
        default: 'pending'
    },
    assignedKey: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Key',
        default: null
    },
    txid: {
        type: String
    },
    pixCopiaECola: {
        type: String
    },
    pixQrCodeImage: {
        type: String
    },
    customer: {
        name: String,
        cpf: String,
        email: String
    }
}, { timestamps: true });

OrderSchema.index({ status: 1 });

module.exports = mongoose.model('Order', OrderSchema);