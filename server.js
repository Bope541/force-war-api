'use strict';

/* =========================================
   ENV — SEMPRE PRIMEIRO
========================================= */
require('dotenv').config();

/* =========================================
   IMPORTS
========================================= */
const express = require('express');

/* =========================================
   APP
========================================= */
const app = express();
app.use(express.json());

/* =========================================
   ROTAS DE VIDA (OBRIGATÓRIAS)
========================================= */
app.get('/', (req, res) => {
  res.status(200).send('INVICT API ONLINE');
});

app.get('/health', (req, res) => {
  res.status(200).json({ ok: true });
});

app.get('/favicon.ico', (req, res) => {
  res.status(204).end();
});

/* =========================================
   ROTA DE TESTE (API REAL)
========================================= */
app.get('/api/ping', (req, res) => {
  res.json({
    api: 'invict',
    status: 'online',
    time: new Date().toISOString()
  });
});

/* =========================================
   LISTEN — ÚNICA COISA QUE IMPORTA
========================================= */
const PORT = process.env.PORT || 8080;

app.listen(PORT, '0.0.0.0', () => {
  console.log('🚀 INVICT API ESCUTANDO NA PORTA', PORT);
});

/* =========================================
   PROTEÇÃO (NÃO DEIXA MORRER)
========================================= */
process.on('uncaughtException', err => {
  console.error('❌ Uncaught Exception:', err);
});

process.on('unhandledRejection', err => {
  console.error('❌ Unhandled Rejection:', err);
});
