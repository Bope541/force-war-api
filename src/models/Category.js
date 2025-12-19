const mongoose = require('mongoose');

const CategorySchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    // O 'slug' é a versão do nome amigável para URLs
    slug: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    }
}, { timestamps: true });

// Middleware para criar o 'slug' automaticamente
CategorySchema.pre('validate', function(next) {
    if (this.name && this.isModified('name')) {
        this.slug = this.name.toString().toLowerCase()
            .replace(/\s+/g, '-')           // Substitui espaços por hífens
            .replace(/[^\w\-]+/g, '')       // Remove caracteres não-palavra
            .replace(/\-\-+/g, '-')         // Substitui múltiplos hífens por um
            .replace(/^-+/, '')             // Remove hífens do início
            .replace(/-+$/, '');            // Remove hífens do fim
    }
    next();
});

module.exports = mongoose.model('Category', CategorySchema);