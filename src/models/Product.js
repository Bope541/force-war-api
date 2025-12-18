const mongoose = require('mongoose');

// Um sub-documento para os planos
const PlanSchema = new mongoose.Schema({
    name: { type: String, required: true },
    price: { type: Number, required: true }
});

// Sub-schema para o estoque de chaves
const KeyStockSchema = new mongoose.Schema({
    key: { type: String, required: true, uppercase: true },
    isSold: { type: Boolean, default: false },
    soldTo: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    orderId: { type: mongoose.Schema.Types.ObjectId, ref: 'Order', default: null }
});

const ProductSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    slug: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    description: {
        type: String,
        required: true
    },
    
    // --- (MUDANÇA CRÍTICA) ---
    // 'category' já não é uma String com 'enum'.
    // Agora é uma referência ao documento da Categoria.
    category: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Category',
        required: true
    },
    // --- FIM DA MUDANÇA ---
    
    imageUrls: {
        type: [String],
        required: true,
        validate: [v => Array.isArray(v) && v.length > 0, 'O produto deve ter pelo menos uma imagem.']
    },
    plans: [PlanSchema],
    platform: { type: String, default: 'Windows 10/11' },
    productType: { type: String, default: 'External' },
    warranty: { type: String, default: '7 dias' },
    keys: [KeyStockSchema],
    isDetectado: { type: Boolean, default: true },
    rating: { type: Number, default: 5.0 }
}, { timestamps: true });

// Middleware para criar o 'slug'
ProductSchema.pre('validate', function(next) {
    if (this.name && this.isModified('name')) {
        this.slug = this.name.toString().toLowerCase()
            .replace(/\s+/g, '-')
            .replace(/[^\w\-]+/g, '')
            .replace(/\-\-+/g, '-')
            .replace(/^-+/, '')
            .replace(/-+$/, '');
    }
    next();
});

module.exports = mongoose.model('Product', ProductSchema);