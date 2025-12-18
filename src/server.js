'use strict';

require('dotenv').config();

const express = require('express');
const app = express();

// rotas básicas
app.get('/', (req, res) => res.send('API ONLINE'));
app.get('/health', (req, res) => res.json({ ok: true }));
app.get('/favicon.ico', (req, res) => res.status(204).end());

// listen
const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => {
  console.log('🚀 API VIVA NA PORTA', PORT);
});

// mantém o processo vivo (Railway edge-safe)
setInterval(() => {
  console.log('⏳ keep-alive');
}, 30000);
