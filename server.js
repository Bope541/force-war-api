'use strict';

/* =====================================================
   🔥 ENV — SEMPRE PRIMEIRO
===================================================== */
require('dotenv').config();

/* =====================================================
   IMPORTS
===================================================== */
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');

/* =====================================================
   APP
===================================================== */
const app = express();

/* =====================================================
   MIDDLEWARES BÁSICOS
===================================================== */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* =====================================================
   ROTAS DE VIDA (CRÍTICAS NO RAILWAY)
===================================================== */
app.get('/', (req, res) => {
  res.status(200).send('API ONLINE');
});

app.get('/health', (req, res) => {
  res.status(200).json({ ok: true });
});

app.get('/favicon.ico', (req, res) => {
  res.status(204).end();
});

/* =====================================================
   LISTEN — IMEDIATO (NÃO BLOQUEIA)
===================================================== */
const PORT = process.env.PORT || 8080;

app.listen(PORT, '0.0.0.0', () => {
  console.log('🚀 SERVER ESCUTANDO NA PORTA', PORT);
});

/* =====================================================
   INICIALIZAÇÕES EM BACKGROUND
===================================================== */
(async () => {
  try {
    console.log('🔄 Inicializando serviços...');

    /* ---------- MongoDB ---------- */
    if (!process.env.MONGODB_URI) {
      console.warn('⚠️ MONGODB_URI não definida (Mongo desativado)');
    } else {
      await mongoose.connect(process.env.MONGODB_URI);
      console.log('✅ MongoDB conectado');
    }

    /* ---------- Session ---------- */
    app.use(session({
      name: 'invict.sid',
      secret: process.env.SESSION_SECRET || 'invict_secret_dev',
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
      }
    }));

    /* ---------- Passport ---------- */
    app.use(passport.initialize());
    app.use(passport.session());

    console.log('✅ Serviços carregados com sucesso');
  } catch (err) {
    console.error('❌ Erro ao inicializar serviços:', err);
  }
})();

/* =====================================================
   EXEMPLO DE ROTA REAL (API)
===================================================== */
app.get('/api/public/ping', (req, res) => {
  res.json({
    api: 'invict',
    status: 'online',
    time: new Date().toISOString()
  });
});

/* =====================================================
   PROTEÇÃO FINAL (NÃO DEIXA MORRER)
===================================================== */
process.on('uncaughtException', err => {
  console.error('❌ Uncaught Exception:', err);
});

process.on('unhandledRejection', err => {
  console.error('❌ Unhandled Rejection:', err);
});
