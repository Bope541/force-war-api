'use strict';

// =====================================
// ENV
// =====================================
require('dotenv').config();

// =====================================
// IMPORTS
// =====================================
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');

// =====================================
// APP
// =====================================
const app = express();
app.use(express.json());

// =====================================
// CORS (libera seu frontend)
// =====================================
const allowedOrigins = (process.env.CORS_ORIGIN || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

app.use(cors({
  origin: allowedOrigins.length ? allowedOrigins : true,
  credentials: true
}));

// =====================================
// ROTAS BÁSICAS (PROVA DE VIDA)
// =====================================
app.get('/', (req, res) => {
  res.send('FORCE WAR API ONLINE');
});

app.get('/health', (req, res) => {
  res.json({ ok: true });
});

app.get('/favicon.ico', (req, res) => {
  res.status(204).end();
});

// =====================================
// EXEMPLO DE ROTA REAL
// =====================================
app.get('/api/public/categories', async (req, res) => {
  try {
    const categories = await mongoose.connection
      .collection('categories')
      .find({})
      .sort({ name: 1 })
      .toArray();

    res.json(categories);
  } catch (err) {
    console.error('Erro categories:', err);
    res.status(500).json({ message: 'Erro interno' });
  }
});

// =====================================
// LISTEN (CRÍTICO)
// =====================================
const PORT = process.env.PORT || 8080;

app.listen(PORT, '0.0.0.0', () => {
  console.log('🚀 FORCE WAR API ESCUTANDO NA PORTA', PORT);
});

// =====================================
// MONGO (DEPOIS DO LISTEN)
// =====================================
(async () => {
  try {
    if (!process.env.MONGODB_URI) {
      console.warn('⚠️ MONGODB_URI não definida');
      return;
    }

    await mongoose.connect(process.env.MONGODB_URI);
    console.log('✅ Mongo conectado');
  } catch (err) {
    console.error('❌ Erro Mongo:', err.message);
  }
})();
