const mongoose = require('mongoose');

const CouponSchema = new mongoose.Schema({
    // O código que o usuário digita (ex: BEMVINDO10)
    code: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        uppercase: true
    },
    // 'percentage' (ex: 10) ou 'fixed' (ex: 500 para R$5,00)
    discountType: {
        type: String,
        enum: ['percentage', 'fixed'],
        required: true
    },
    // O valor do desconto
    discountValue: {
        type: Number,
        required: true
    },
    // Data de expiração do cupom
    expiresAt: {
        type: Date
    },
    // Valor mínimo da compra (em centavos) para o cupom ser válido
    minPurchase: {
        type: Number,
        default: 0
    },
    // Array de IDs de Produtos. Se estiver vazio, aplica-se a todos.
    applicableProducts: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Product'
    }],
    // Quantas vezes foi usado
    uses: {
        type: Number,
        default: 0
    },
    // Limite máximo de usos
    maxUses: {
        type: Number,
        default: 1 // Por padrão, só pode ser usado 1 vez
    },
    // Para desativar o cupom rapidamente
    isActive: {
        type: Boolean,
        default: true
    }
}, { timestamps: true });

module.exports = mongoose.model('Coupon', CouponSchema);