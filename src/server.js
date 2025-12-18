'use strict';

require('dotenv').config(); // 🔥 SEMPRE PRIMEIRO

console.log('🔥 SERVER INICIANDO');
const express = require('express');
const path = require('path');
const fs = require('fs');

const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const LocalStrategy = require('passport-local').Strategy;

console.log('🔥 SERVER.JS DA API CARREGADO');

// ==================================================
// CORS (CORRETO PARA credentials: 'include')
// ==================================================
// Defina no Railway:
// FRONTEND_ORIGIN=https://SEU-SITE.com
// (se tiver mais de um, use separado por vírgula)
const allowedOrigins = (process.env.FRONTEND_ORIGIN || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

const app = express();

// 🔐 IMPORTANTE PARA Railway / Proxy / HTTPS
app.set('trust proxy', 1);

// Middleware CORS seguro
app.use((req, res, next) => {
  const origin = req.headers.origin;

  // Se houver origins configuradas, valida. Se não houver, não libera credentials.
  if (origin && allowedOrigins.length > 0 && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin'); // evita cache errado por origem
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  } else if (origin && allowedOrigins.length === 0) {
    // Sem whitelist definida: ainda responde, mas SEM credentials (evita configuração inválida)
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }

  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, X-Requested-With'
  );
  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET,POST,PUT,PATCH,DELETE,OPTIONS'
  );

  // Preflight
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }

  return next();
});

// Healthcheck (ótimo pro Railway)
app.get('/health', (req, res) => {
  res.status(200).json({ ok: true, uptime: process.uptime() });
});

app.get('/', (req, res) => res.status(200).send('API ONLINE'));
app.get('/health', (req, res) => res.status(200).json({ ok: true }));
app.get('/favicon.ico', (req, res) => res.status(204).end());

// ==================================================
// DEPENDÊNCIAS DE APP
// ==================================================
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { Resend } = require('resend');

const Gerencianet = require('gn-api-sdk-node');

// --- MODELOS ---
const User = require('./models/User');
const Order = require('./models/Order');
const Product = require('./models/Product');
const Key = require('./models/Key');
const Coupon = require('./models/Coupon');
const Affiliate = require('./models/Affiliate');
const Category = require('./models/Category'); // (NOVO)

// ===============================
// CONFIGURAÇÃO DO BANCO DE DADOS
// ===============================
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.error('❌ MONGODB_URI não definida — API sobe sem banco');
} else {
  mongoose
    .connect(MONGODB_URI)
    .then(() => console.log('✅ Conectado ao MongoDB!'))
    .catch(err => console.error('❌ Erro ao conectar no MongoDB:', err.message));
}

// --- CONFIGURAÇÃO DO RESEND ---
const resend = new Resend(process.env.RESEND_API_KEY);

// ===============================
// EFI / GERENCIANET (NUNCA DERRUBA O BOOT)
// ===============================
let efi = null;
let efiReady = false;

try {
  const hasBase64 = !!process.env.EFI_CERTIFICADO_BASE64;
  const hasCreds = !!process.env.EFI_CLIENT_ID && !!process.env.EFI_CLIENT_SECRET;

  if (!hasCreds) {
    console.warn('⚠️ EFI_CLIENT_ID/EFI_CLIENT_SECRET ausentes — PIX desativado');
  } else if (!hasBase64) {
    console.warn('⚠️ EFI_CERTIFICADO_BASE64 ausente — PIX desativado (Railway não usa path local)');
  } else {
    const certBuffer = Buffer.from(process.env.EFI_CERTIFICADO_BASE64, 'base64');

    efi = new Gerencianet({
      sandbox: process.env.EFI_SANDBOX === 'true',
      client_id: process.env.EFI_CLIENT_ID,
      client_secret: process.env.EFI_CLIENT_SECRET,
      certificate: certBuffer,
    });

    efiReady = true;
    console.log('✅ EFI inicializado com sucesso');
  }
} catch (err) {
  console.error('❌ EFI falhou — PIX desativado:', err.message);
  efi = null;
  efiReady = false;
}

//-- Revisado!

// ==================================================
// HELPERS
// ==================================================
function isPasswordStrong(password) {
  const minLength = 8;
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSymbol = /[^A-Za-z0-9]/.test(password);
  return (
    password.length >= minLength &&
    hasUpper &&
    hasLower &&
    hasNumber &&
    hasSymbol
  );
}

// ==================================================
// BODY PARSERS
// ==================================================
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// ⚠️ OPTIONS JÁ É TRATADO NO CORS GLOBAL
// (manter apenas se quiser explícito — não quebra)
// app.options('*', (req, res) => res.sendStatus(204));

// ==================================================
// SESSION (CONFIGURAÇÃO SEGURA PARA RAILWAY)
// ==================================================
const isProd = process.env.NODE_ENV === 'production';

app.use(
  session({
    name: 'forcewar.sid',
    secret: process.env.SESSION_SECRET || 'force-war-dev-secret',
    resave: false,
    saveUninitialized: false,
    proxy: true, // 🔑 obrigatório atrás de proxy (Railway)
    cookie: {
      secure: isProd,      // HTTPS em produção
      sameSite: 'lax',
      httpOnly: true,
    },
  })
);

// ==================================================
// PASSPORT
// ==================================================
app.use(passport.initialize());
app.use(passport.session());

// ===============================
// LOCAL STRATEGY
// ===============================
passport.use(
  new LocalStrategy(
    { usernameField: 'username_email' },
    async (username_email, password, done) => {
      try {
        const user = await User.findOne({
          $or: [
            { email: username_email },
            { username: username_email },
          ],
        });

        if (!user) {
          return done(null, false, {
            message: 'Usuário ou senha inválidos.',
          });
        }

        if (user.provider === 'discord') {
          return done(null, false, {
            message:
              'Esta conta foi registrada com o Discord. Faça login com o Discord.',
          });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          return done(null, false, {
            message: 'Usuário ou senha inválidos.',
          });
        }

        return done(null, user);
      } catch (err) {
        console.error('❌ LocalStrategy erro:', err);
        return done(err);
      }
    }
  )
);

// ===============================
// DISCORD STRATEGY
// ===============================
passport.use(
  new DiscordStrategy(
    {
      clientID: process.env.DISCORD_CLIENT_ID || '',
      clientSecret: process.env.DISCORD_CLIENT_SECRET || '',
      callbackURL: process.env.DISCORD_CALLBACK_URL,
      scope: ['identify', 'email'],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const { id, username, email, avatar } = profile;

        let user = await User.findOne({ discordId: id });
        if (user) return done(null, user);

        user = await User.findOne({ email });
        if (user) {
          user.discordId = id;
          user.avatar = avatar;
          user.provider = 'discord';
          await user.save();
          return done(null, user);
        }

        const newUser = new User({
          discordId: id,
          username,
          email,
          avatar,
          provider: 'discord',
        });

        await newUser.save();
        return done(null, newUser);
      } catch (err) {
        console.error('❌ DiscordStrategy erro:', err);
        return done(err, null);
      }
    }
  )
);

// ===============================
// SERIALIZAÇÃO
// ===============================
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    return done(null, user || false);
  } catch (err) {
    console.error('❌ deserializeUser erro:', err);
    return done(err, null);
  }
});

//-- Revisado!

// ==================================================
// MIDDLEWARES DE AUTENTICAÇÃO (BLINDADOS)
// ==================================================
function requireAuthPage(req, res, next) {
  if (typeof req.isAuthenticated === 'function' && req.isAuthenticated()) {
    return next();
  }
  return res.redirect('/login');
}

function isAdmin(req, res, next) {
  if (
    typeof req.isAuthenticated === 'function' &&
    req.isAuthenticated() &&
    req.user &&
    req.user.role === 'admin'
  ) {
    return next();
  }

  console.warn(
    `[Segurança] Acesso admin negado: ${
      req.user?.username || 'Guest'
    }`
  );

  return res.redirect('/');
}

// --- (NOVO) Middleware para checar se é Afiliado ---
async function isAffiliate(req, res, next) {
  try {
    if (
      typeof req.isAuthenticated !== 'function' ||
      !req.isAuthenticated() ||
      !req.user
    ) {
      return res.status(401).json({ message: 'Não autorizado' });
    }

    const affiliate = await Affiliate.findOne({
      user: req.user.id,
      status: 'active',
    });

    if (!affiliate) {
      return res
        .status(403)
        .json({ message: 'Acesso negado. Você não é um afiliado ativo.' });
    }

    req.affiliate = affiliate;
    return next();
  } catch (err) {
    console.error('❌ isAffiliate erro:', err);
    return res.status(500).json({ message: 'Erro interno' });
  }
}

// ==================================================
// ARQUIVOS ESTÁTICOS
// ==================================================
const PUBLIC_DIR = path.join(__dirname, '../public');
app.use(express.static(PUBLIC_DIR));

// ==================================================
// ROTAS DE AUTENTICAÇÃO
// ==================================================
app.get('/login', (req, res) => {
  if (req.isAuthenticated?.()) return res.redirect('/');
  res.sendFile(path.join(PUBLIC_DIR, 'login.html'));
});

app.get('/register', (req, res) => {
  if (req.isAuthenticated?.()) return res.redirect('/');
  res.sendFile(path.join(PUBLIC_DIR, 'register.html'));
});

app.get('/forgot-password', (req, res) => {
  if (req.isAuthenticated?.()) return res.redirect('/');
  res.sendFile(path.join(PUBLIC_DIR, 'forgot-password.html'));
});

app.get('/pagamento-pix.html', requireAuthPage, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'pagamento-pix.html'));
});

// ==================================================
// CONTA
// ==================================================
app.get('/minha-conta', requireAuthPage, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'minha-conta.html'));
});

app.get('/meus-pedidos', requireAuthPage, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'meus-pedidos.html'));
});

app.get('/pedido-detalhes', requireAuthPage, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'pedido-detalhes.html'));
});

// ==================================================
// AFILIADO
// ==================================================
app.get('/affiliate-dashboard.html', requireAuthPage, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'affiliate-dashboard.html'));
});

// ==================================================
// ADMIN
// ==================================================
app.get('/admin', requireAuthPage, isAdmin, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'admin.html'));
});

app.get('/admin/products', requireAuthPage, isAdmin, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'admin-products.html'));
});

app.get('/admin/coupons', requireAuthPage, isAdmin, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'admin-coupons.html'));
});

app.get('/admin/affiliates', requireAuthPage, isAdmin, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'admin-affiliates.html'));
});

app.get('/admin/withdrawals', requireAuthPage, isAdmin, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'admin-withdrawals.html'));
});

app.get('/admin/categories', requireAuthPage, isAdmin, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'admin-categories.html'));
});

//-- Revisado!

// ==================================================
// ROTAS DE AUTENTICAÇÃO
// ==================================================
app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    console.log(`[Registro] Tentativa de registro para: ${email}`);

    const redirectWithError = (message) => {
      console.log(`[Registro] Erro: ${message}`);
      return res.redirect(`/register?error=${encodeURIComponent(message)}`);
    };

    if (!username || !email || !password) {
      return redirectWithError('Por favor, preencha todos os campos.');
    }

    if (!isPasswordStrong(password)) {
      return redirectWithError(
        'Sua senha não atende aos requisitos mínimos de segurança.'
      );
    }

    const existingUser = await User.findOne({
      $or: [{ email }, { username }],
    });

    if (existingUser) {
      return redirectWithError('Email ou nome de usuário já cadastrado.');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      username,
      email,
      password: hashedPassword,
      provider: 'local',
    });

    await user.save();
    console.log('[Registro] Usuário criado. Tentando auto-login...');

    if (typeof req.logIn !== 'function') {
      console.warn('[Registro] req.logIn indisponível');
      return res.redirect('/login');
    }

    req.logIn(user, (err) => {
      if (err) {
        console.error('[Registro] Erro no auto-login:', err);
        return res.redirect('/login');
      }
      console.log('[Registro] Auto-login realizado com sucesso');
      return res.redirect('/');
    });
  } catch (err) {
    console.error('[Registro] Erro crítico:', err);

    if (err?.code === 11000) {
      return res.redirect(
        `/register?error=${encodeURIComponent(
          'Email ou nome de usuário já cadastrado.'
        )}`
      );
    }

    return res.redirect(
      `/register?error=${encodeURIComponent(
        'Erro interno do servidor. Tente mais tarde.'
      )}`
    );
  }
});

// ==================================================
// LOGIN
// ==================================================
app.post('/login', (req, res, next) => {
  if (!passport || typeof passport.authenticate !== 'function') {
    console.error('[Login] Passport não inicializado');
    return res.redirect('/login?error=Erro interno');
  }

  passport.authenticate('local', (err, user, info = {}) => {
    try {
      if (err) {
        console.error('[Login] Erro no authenticate:', err);
        return next(err);
      }

      if (!user) {
        const errorMsg = info.message || 'Falha no login.';
        return res.redirect(
          `/login?error=${encodeURIComponent(errorMsg)}`
        );
      }

      if (typeof req.logIn !== 'function') {
        console.error('[Login] req.logIn indisponível');
        return res.redirect('/login');
      }

      req.logIn(user, (err) => {
        if (err) {
          console.error('[Login] Erro no logIn:', err);
          return next(err);
        }

        if (user.role === 'admin') {
          console.log(`[Login] Admin ${user.username} logado`);
          return res.redirect('/admin');
        }

        console.log(`[Login] Usuário ${user.username} logado`);
        return res.redirect('/');
      });
    } catch (fatalErr) {
      console.error('[Login] Erro fatal:', fatalErr);
      return next(fatalErr);
    }
  })(req, res, next);
});

// ==================================================
// DISCORD AUTH
// ==================================================
app.get('/auth/discord', (req, res, next) => {
  if (!passport || typeof passport.authenticate !== 'function') {
    console.error('[Discord Auth] Passport não inicializado');
    return res.redirect('/login?error=Erro interno');
  }
  return passport.authenticate('discord')(req, res, next);
});

app.get(
  '/auth/discord/callback',
  passport.authenticate('discord', { failureRedirect: '/login' }),
  (req, res) => {
    return res.redirect('/');
  }
);

// ==================================================
// LOGOUT
// ==================================================
app.get('/logout', (req, res, next) => {
  if (typeof req.logout !== 'function') {
    console.warn('[Logout] req.logout indisponível');
    return res.redirect('/');
  }

  req.logout((err) => {
    if (err) {
      console.error('[Logout] Erro:', err);
      return next(err);
    }
    return res.redirect('/');
  });
});

// ==================================================
// API — RESET DE SENHA
// ==================================================
app.post('/api/request-reset', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.json({ success: true });
    }

    const user = await User.findOne({
      email,
      provider: 'local',
    });

    if (user) {
      const code = crypto.randomInt(100000, 999999).toString();
      const expires = Date.now() + 10 * 60 * 1000;

      user.resetPasswordCode = await bcrypt.hash(code, 10);
      user.resetPasswordExpires = expires;
      await user.save();

      if (!resend || !resend.emails) {
        console.error('[Reset Senha] Resend não configurado');
        return res
          .status(500)
          .json({ message: 'Serviço de email indisponível.' });
      }

      try {
        await resend.emails.send({
          from: 'Invict <onboarding@resend.dev>',
          to: user.email,
          subject: 'Seu código de recuperação de senha - Invict',
          html: `
            <h1>Recuperação de Senha</h1>
            <p>Seu código de 6 dígitos:</p>
            <h2 style="letter-spacing:4px">${code}</h2>
            <p>Este código expira em 10 minutos.</p>
          `,
        });

        console.log(`[Reset Senha] Código enviado para ${user.email}`);
      } catch (emailErr) {
        console.error('[Reset Senha] Erro ao enviar email:', emailErr);
        return res
          .status(500)
          .json({ message: 'Erro ao enviar email.' });
      }
    } else {
      console.log(
        `[Reset Senha] Tentativa para e-mail inexistente: ${email}`
      );
    }

    return res.json({ success: true });
  } catch (err) {
    console.error('[Reset Senha] Erro crítico:', err);
    return res
      .status(500)
      .json({ message: 'Erro interno do servidor.' });
  }
});

//-- Revisado!

// ==================================================
// AUTH API (BLINDADO) — use este no lugar de isAuthenticated
// ==================================================
function isAuthenticatedApi(req, res, next) {
  try {
    if (typeof req.isAuthenticated === 'function' && req.isAuthenticated() && req.user) {
      return next();
    }
    return res.status(401).json({ message: 'Não autorizado' });
  } catch (err) {
    console.error('❌ isAuthenticatedApi erro:', err);
    return res.status(401).json({ message: 'Não autorizado' });
  }
}

// ==================================================
// RESET DE SENHA — VERIFICAR CÓDIGO
// ==================================================
app.post('/api/verify-code', async (req, res) => {
  try {
    const { email, code } = req.body || {};

    if (!email || !code) {
      return res.status(400).json({ message: 'Informe email e código.' });
    }

    const user = await User.findOne({
      email,
      provider: 'local',
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user || !user.resetPasswordCode) {
      return res.status(400).json({ message: 'Código expirado ou inválido.' });
    }

    const isMatch = await bcrypt.compare(String(code), String(user.resetPasswordCode));
    if (!isMatch) {
      return res.status(400).json({ message: 'Código incorreto.' });
    }

    return res.json({ success: true, username: user.username });
  } catch (err) {
    console.error('[Reset Senha] Erro ao verificar código:', err);
    return res.status(500).json({ message: 'Erro interno do servidor.' });
  }
});

// ==================================================
// RESET DE SENHA — DEFINIR NOVA SENHA
// ==================================================
app.post('/api/set-new-password', async (req, res) => {
  try {
    const { email, code, newPassword } = req.body || {};

    if (!email || !code || !newPassword) {
      return res.status(400).json({ message: 'Informe email, código e nova senha.' });
    }

    if (!isPasswordStrong(newPassword)) {
      return res.status(400).json({
        message: 'Sua senha não atende aos requisitos mínimos de segurança.',
      });
    }

    const user = await User.findOne({
      email,
      provider: 'local',
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user || !user.resetPasswordCode) {
      return res.status(400).json({ message: 'Sessão de redefinição inválida. Tente novamente.' });
    }

    const isMatch = await bcrypt.compare(String(code), String(user.resetPasswordCode));
    if (!isMatch) {
      return res.status(400).json({ message: 'Sessão de redefinição inválida. Tente novamente.' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.resetPasswordCode = undefined;
    user.resetPasswordExpires = undefined;

    await user.save();

    console.log(`[Reset Senha] Senha redefinida com sucesso para ${user.email}`);
    return res.json({ success: true });
  } catch (err) {
    console.error('[Reset Senha] Erro ao salvar:', err);
    return res.status(500).json({ message: 'Erro interno do servidor.' });
  }
});

// ==================================================
// ROTAS DE API — CONTA
// ==================================================
app.get('/api/account/info', isAuthenticatedApi, async (req, res) => {
  try {
    const userId = req.user?.id || req.user?._id;
    if (!userId) {
      return res.status(401).json({ message: 'Não autorizado' });
    }

    const user = await User.findById(userId).lean();
    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado.' });
    }

    // Remove campos sensíveis
    delete user.password;
    delete user.resetPasswordCode;
    delete user.resetPasswordExpires;

    return res.json(user);
  } catch (err) {
    console.error('Erro ao buscar dados da conta:', err);
    return res.status(500).json({ message: 'Erro interno do servidor.' });
  }
});

app.post('/api/account/redeem', isAuthenticatedApi, async (req, res) => {
  try {
    const { keyString } = req.body || {};
    const userId = req.user?.id || req.user?._id;

    if (!userId) {
      return res.status(401).json({ message: 'Não autorizado' });
    }

    if (!keyString || typeof keyString !== 'string') {
      return res.status(400).json({ message: 'Por favor, insira uma chave.' });
    }

    const key = await Key.findOne({ keyString: keyString.toUpperCase().trim() });
    if (!key) {
      return res.status(404).json({ message: 'Chave inválida ou não encontrada.' });
    }
    if (key.isRedeemed) {
      return res.status(400).json({ message: 'Esta chave já foi resgatada.' });
    }

    let expiresAt = null;
    if (key.durationInDays > 0) {
      expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + key.durationInDays);
    } else if (key.durationInDays === -1) {
      expiresAt = new Date();
      expiresAt.setFullYear(expiresAt.getFullYear() + 100);
    }

    const newSubscription = {
      productName: key.productName,
      planName: key.planName,
      expiresAt,
      keyUsed: key.keyString,
    };

    key.isRedeemed = true;
    key.redeemedBy = userId;
    key.redeemedAt = new Date();

    await key.save();

    await User.findByIdAndUpdate(
      userId,
      { $push: { activeSubscriptions: newSubscription } },
      { new: true }
    );

    return res.status(200).json({
      message: 'Chave resgatada com sucesso!',
      subscription: newSubscription,
    });
  } catch (err) {
    console.error('Erro ao resgatar key:', err);
    return res.status(500).json({ message: 'Erro interno do servidor.' });
  }
});

//-- revisado!

// ==================================================
// AUTH API (BLINDADO)
// ==================================================
function isAuthenticatedApi(req, res, next) {
  try {
    if (typeof req.isAuthenticated === 'function' && req.isAuthenticated() && req.user) {
      return next();
    }
    return res.status(401).json({ message: 'Não autorizado' });
  } catch (err) {
    console.error('❌ isAuthenticatedApi erro:', err);
    return res.status(401).json({ message: 'Não autorizado' });
  }
}

// ==================================================
// PEDIDOS DO USUÁRIO
// ==================================================
app.get('/api/account/orders', isAuthenticatedApi, async (req, res) => {
  try {
    const userId = req.user.id || req.user._id;

    const orders = await Order.find({ user: userId })
      .sort({ createdAt: -1 })
      .lean();

    return res.json(orders);
  } catch (err) {
    console.error('Erro ao buscar pedidos:', err);
    return res.status(500).json({ message: 'Erro ao buscar pedidos.' });
  }
});

app.get('/api/account/orders/:id', isAuthenticatedApi, async (req, res) => {
  try {
    const userId = req.user.id || req.user._id;

    const order = await Order.findById(req.params.id).lean();
    if (!order) {
      return res.status(404).json({ message: 'Pedido não encontrado.' });
    }

    if (order.user.toString() !== userId.toString()) {
      return res.status(403).json({ message: 'Acesso negado.' });
    }

    return res.json(order);
  } catch (err) {
    console.error('Erro ao buscar pedido:', err);
    return res.status(500).json({ message: 'Erro ao buscar pedido.' });
  }
});

// ==================================================
// VALIDAR CUPOM
// ==================================================
app.post('/api/validate-coupon', isAuthenticatedApi, async (req, res) => {
  try {
    const { couponCode, productId, subtotal } = req.body || {};

    if (!couponCode || !productId || typeof subtotal !== 'number') {
      return res.status(400).json({ message: 'Dados inválidos.' });
    }

    const coupon = await Coupon.findOne({ code: couponCode });
    if (!coupon) {
      return res.status(404).json({ message: 'Cupom não encontrado.' });
    }
    if (!coupon.isActive) {
      return res.status(400).json({ message: 'Este cupom está desativado.' });
    }
    if (coupon.expiresAt && coupon.expiresAt < new Date()) {
      return res.status(400).json({ message: 'Este cupom expirou.' });
    }
    if (coupon.maxUses && coupon.uses >= coupon.maxUses) {
      return res.status(400).json({ message: 'Este cupom atingiu o limite de usos.' });
    }
    if (subtotal < coupon.minPurchase) {
      return res.status(400).json({
        message: `Esta compra não atingiu o valor mínimo de R$ ${(coupon.minPurchase / 100).toFixed(2)}.`,
      });
    }

    if (Array.isArray(coupon.applicableProducts) && coupon.applicableProducts.length > 0) {
      const isApplicable = coupon.applicableProducts.some(
        id => id.toString() === productId.toString()
      );
      if (!isApplicable) {
        return res.status(400).json({ message: 'Este cupom não é válido para este produto.' });
      }
    }

    let discountAmount = 0;
    if (coupon.discountType === 'percentage') {
      discountAmount = Math.round(subtotal * (coupon.discountValue / 100));
    } else {
      discountAmount = coupon.discountValue;
    }

    if (discountAmount > subtotal) discountAmount = subtotal;

    return res.json({
      message: 'Cupom aplicado com sucesso!',
      discountAmount,
      discountType: coupon.discountType,
      discountValue: coupon.discountValue,
    });
  } catch (error) {
    console.error('Erro ao validar cupom:', error);
    return res.status(500).json({ message: 'Erro interno do servidor.' });
  }
});

// ==================================================
// STATUS DE AUTENTICAÇÃO
// ==================================================
app.get('/api/auth/status', async (req, res) => {
  try {
    if (typeof req.isAuthenticated === 'function' && req.isAuthenticated() && req.user) {
      const affiliate = await Affiliate.findOne({
        user: req.user.id || req.user._id,
        status: 'active',
      });

      return res.json({
        loggedIn: true,
        user: {
          username: req.user.username,
          avatar: req.user.avatar,
          discordId: req.user.discordId,
        },
        isAffiliate: !!affiliate,
      });
    }

    return res.json({ loggedIn: false });
  } catch (err) {
    console.error('Erro em /api/auth/status:', err);
    return res.json({ loggedIn: false });
  }
});

//-- Revisado!

// ==================================================
// AUTH API (BLINDADO)
// ==================================================
function isAuthenticatedApi(req, res, next) {
  try {
    if (typeof req.isAuthenticated === 'function' && req.isAuthenticated() && req.user) {
      return next();
    }
    return res.status(401).send('Não autorizado');
  } catch (err) {
    console.error('❌ isAuthenticatedApi erro:', err);
    return res.status(401).send('Não autorizado');
  }
}

// ==================================================
// CRIAR PAGAMENTO PIX (EFI)
// ==================================================
app.post('/criar-pagamento', isAuthenticatedApi, async (req, res) => {
  console.log('[Pagamento] Recebida requisição /criar-pagamento');

  // 🚨 BLOQUEIO DURO SE EFI NÃO ESTIVER DISPONÍVEL
  if (!efiReady || !efi || !CHAVE_PIX) {
    return res
      .status(503)
      .send('Pagamento PIX temporariamente indisponível. Tente novamente mais tarde.');
  }

  try {
    const {
      full_name,
      cpf,
      email,
      productId,
      productTitle,
      productPlan,
      productPrice,
      couponApplied,
      discountAmount,
      finalTotal,
    } = req.body || {};

    const userId = req.user.id || req.user._id;

    if (
      !full_name ||
      !cpf ||
      !email ||
      !productId ||
      !productTitle ||
      !productPlan ||
      productPrice == null ||
      finalTotal == null
    ) {
      return res.status(400).send('Dados incompletos. Volte e tente novamente.');
    }

    const orderNumber = `INV-${Date.now().toString().slice(-6)}`;

    // ==================================================
    // NORMALIZAÇÃO DE VALORES
    // ==================================================
    const toCents = (value) => {
      if (typeof value === 'number') return Math.round(value * 100);
      if (typeof value === 'string') {
        const parsed = parseFloat(value.replace(',', '.'));
        return Number.isFinite(parsed) ? Math.round(parsed * 100) : NaN;
      }
      return NaN;
    };

    const subtotalInCents = toCents(productPrice);
    const frontendTotalCents = toCents(finalTotal);

    if (!Number.isFinite(subtotalInCents) || !Number.isFinite(frontendTotalCents)) {
      return res.status(400).send('Valores inválidos.');
    }

    let discountInCents = 0;
    let coupon = null;

    // ==================================================
    // CUPOM
    // ==================================================
    if (couponApplied) {
      coupon = await Coupon.findOne({ code: couponApplied });

      if (
        !coupon ||
        !coupon.isActive ||
        (coupon.expiresAt && coupon.expiresAt < new Date()) ||
        (coupon.maxUses && coupon.uses >= coupon.maxUses) ||
        subtotalInCents < coupon.minPurchase
      ) {
        return res.status(400).send('Cupom inválido ou expirado.');
      }

      if (Array.isArray(coupon.applicableProducts) && coupon.applicableProducts.length) {
        const isApplicable = coupon.applicableProducts.some(
          (id) => id.toString() === productId.toString()
        );
        if (!isApplicable) {
          return res.status(400).send('Cupom não aplicável a este produto.');
        }
      }

      discountInCents =
        coupon.discountType === 'percentage'
          ? Math.round(subtotalInCents * (coupon.discountValue / 100))
          : coupon.discountValue;

      if (discountInCents > subtotalInCents) discountInCents = subtotalInCents;

      const frontendDiscountCents = toCents(discountAmount || 0);
      if (frontendDiscountCents !== discountInCents) {
        return res.status(400).send('Disparidade no valor do cupom.');
      }
    }

    const finalAmountInCents = subtotalInCents - discountInCents;
    if (finalAmountInCents !== frontendTotalCents) {
      return res.status(400).send('Disparidade no valor total.');
    }

    const valorStringEfi = (finalAmountInCents / 100).toFixed(2);

    // ==================================================
    // CRIAR PEDIDO
    // ==================================================
    const newOrder = new Order({
      user: userId,
      productId,
      orderNumber,
      productTitle,
      productPlan,
      subtotal: subtotalInCents,
      couponApplied,
      discountAmount: discountInCents,
      amount: finalAmountInCents,
      status: 'pending',
      customer: {
        name: full_name,
        cpf: cpf.replace(/\D/g, ''),
        email,
      },
    });

    // ==================================================
    // PEDIDO GRÁTIS
    // ==================================================
    if (finalAmountInCents <= 0) {
      await newOrder.save();
      await processAndDeliverOrder(newOrder);

      if (coupon) {
        coupon.uses += 1;
        await coupon.save();
      }

      return res.redirect(`/pedido-detalhes.html?id=${newOrder._id}`);
    }

    // ==================================================
    // CRIAR COBRANÇA PIX
    // ==================================================
    const body = {
      calendario: { expiracao: 3600 },
      devedor: {
        cpf: cpf.replace(/\D/g, ''),
        nome: full_name,
      },
      valor: { original: valorStringEfi },
      chave: CHAVE_PIX,
      solicitacaoPagador: `Invict - ${productTitle}`,
    };

    console.log(`[EFI] Criando cobrança PIX R$ ${valorStringEfi}`);

    const pixCharge = await efi.pixCreateImmediateCharge({}, body);

    newOrder.txid = pixCharge.txid;
    newOrder.pixCopiaECola = pixCharge.pixCopiaECola;

    if (pixCharge.loc?.id) {
      const qr = await efi.pixGenerateQRCode({ id: pixCharge.loc.id });
      newOrder.pixQrCodeImage = qr.imagemQrcode;
    }

    await newOrder.save();

    if (coupon) {
      coupon.uses += 1;
      await coupon.save();
    }

    return res.redirect(`/pagamento-pix.html?orderId=${newOrder._id}`);
  } catch (error) {
    console.error('[Pagamento] Erro:', error);
    return res.status(500).send('Erro ao gerar pagamento.');
  }
});

//-- revisado!

// ==================================================
// AUTH API (BLINDADO) — use este em rotas /api
// ==================================================
function isAuthenticatedApi(req, res, next) {
  try {
    if (typeof req.isAuthenticated === 'function' && req.isAuthenticated() && req.user) {
      return next();
    }
    return res.status(401).json({ message: 'Não autorizado' });
  } catch (err) {
    console.error('❌ isAuthenticatedApi erro:', err);
    return res.status(401).json({ message: 'Não autorizado' });
  }
}

// ==================================================
// DETALHES DO PEDIDO
// ==================================================
app.get('/api/order-details/:orderId', isAuthenticatedApi, async (req, res) => {
  try {
    const userId = req.user.id || req.user._id;

    const order = await Order.findById(req.params.orderId).lean();
    if (!order || order.user.toString() !== userId.toString()) {
      return res.status(404).json({ message: 'Pedido não encontrado.' });
    }

    return res.json({
      status: order.status,
      pixCopiaECola: order.pixCopiaECola,
      pixQrCodeImage: order.pixQrCodeImage,
      productTitle: order.productTitle,
      productPlan: order.productPlan,
      amount: (order.amount / 100).toFixed(2),
    });
  } catch (error) {
    console.error('Erro ao buscar detalhes do pedido:', error);
    return res.status(500).json({ message: 'Erro interno.' });
  }
});

// ==================================================
// STATUS DO PEDIDO (POLLING EFI)
// ==================================================
app.get('/api/order-status/:orderId', isAuthenticatedApi, async (req, res) => {
  try {
    const userId = req.user.id || req.user._id;

    let order = await Order.findById(req.params.orderId);
    if (!order || order.user.toString() !== userId.toString()) {
      return res.status(404).json({ message: 'Pedido não encontrado.' });
    }

    // Se estiver pendente, tenta consultar na EFI (apenas se EFI estiver OK)
    if (order.status === 'pending' && order.txid && efiReady && efi) {
      console.log(`[Polling] Verificando status na EFI para txid: ${order.txid}`);

      try {
        const charge = await efi.pixDetailCharge({ txid: order.txid });

        if (charge?.status === 'CONCLUIDA') {
          console.log(`[Polling] Pagamento ${order.txid} confirmado pela EFI.`);

          // Processa entrega (idempotente)
          await processAndDeliverOrder(order);

          // Recarrega do banco pra retornar status atualizado
          order = await Order.findById(req.params.orderId);
        }
      } catch (efiError) {
        console.error(`[Polling] Erro ao consultar EFI: ${efiError?.message || efiError}`);
      }
    }

    return res.json({ status: order.status });
  } catch (error) {
    console.error('Erro em /api/order-status:', error);
    return res.status(500).json({ message: 'Erro interno.' });
  }
});

// ==================================================
// PROCESSAR E ENTREGAR PEDIDO (IDEMPOTENTE E SEGURO)
// ==================================================
async function processAndDeliverOrder(order) {
  try {
    if (!order || order.status !== 'pending') {
      console.log(
        `[Entrega] Pedido ${order?._id || 'N/A'} já processado ou inválido. Status: ${order?.status || 'N/A'}`
      );
      return false;
    }

    console.log(`[Entrega] Processando entrega para o Pedido: ${order._id}`);

    // Recarrega o pedido do DB (evita trabalhar com doc desatualizado)
    const freshOrder = await Order.findById(order._id);
    if (!freshOrder || freshOrder.status !== 'pending') return false;

    const product = await Product.findById(freshOrder.productId);
    if (!product) {
      throw new Error(`Produto ${freshOrder.productId} não encontrado para o pedido ${freshOrder.id}`);
    }

    // ===============================
    // RESERVA DE KEY (SEM CRASH)
    // ===============================
    const keys = Array.isArray(product.keys) ? product.keys : [];
    const keyIndex = keys.findIndex((k) => k && !k.isSold);

    if (keyIndex === -1) {
      console.error(
        `[CRÍTICO] SEM ESTOQUE para o produto ${product.name} (ID: ${product._id})! Pedido ${freshOrder.id} foi pago mas não pôde ser entregue.`
      );

      freshOrder.status = 'paid';
      freshOrder.assignedKey = 'SEM_ESTOQUE_CONTATAR_SUPORTE';
      await freshOrder.save();
      return false;
    }

    const assignedKeyStock = product.keys[keyIndex];

    // Marca como vendida no produto
    product.keys[keyIndex].isSold = true;
    product.keys[keyIndex].soldTo = freshOrder.user;
    product.keys[keyIndex].orderId = freshOrder._id;

    // Atualiza pedido
    freshOrder.assignedKey = assignedKeyStock.key;
    freshOrder.status = 'paid';

    // ===============================
    // DURAÇÃO DO PLANO
    // ===============================
    const plan = Array.isArray(product.plans)
      ? product.plans.find((p) => p?.name === freshOrder.productPlan)
      : null;

    let duration = 0;
    if (plan) {
      if (plan.name === '1 Semana') duration = 7;
      else if (plan.name === '1 Mês') duration = 30;
      else if (plan.name === '3 Meses') duration = 90;
      else if (plan.name === 'Vitalicio') duration = -1;
    }

    // ===============================
    // REGISTRAR KEY PARA RESGATE
    // ===============================
    if (duration !== 0) {
      const newKeyForRedemption = new Key({
        keyString: assignedKeyStock.key,
        productName: freshOrder.productTitle,
        planName: freshOrder.productPlan,
        durationInDays: duration,
        isRedeemed: false,
      });

      try {
        await newKeyForRedemption.save();
        console.log(`[Entrega] Key ${newKeyForRedemption.keyString} registrada na coleção 'Key'.`);
      } catch (keyError) {
        console.warn(
          `[Entrega] Aviso: Não foi possível salvar a key ${assignedKeyStock.key} na coleção 'Key' (pode já existir). Erro: ${keyError?.message || keyError}`
        );
      }
    } else {
      console.warn(
        `[Entrega] Pedido ${freshOrder.id} sem duração definida. Key não registrada para resgate.`
      );
    }

    // ===============================
    // COMISSÃO DE AFILIADO (SEM CRASH)
    // ===============================
    let affiliateId = null;

    if (freshOrder.couponApplied && freshOrder.amount > 0) {
      console.log(
        `[Afiliado] Pedido ${freshOrder.id} usou cupom: ${freshOrder.couponApplied}. Verificando...`
      );

      const coupon = await Coupon.findOne({ code: freshOrder.couponApplied });
      if (coupon) {
        const affiliate = await Affiliate.findOne({
          linkedCoupons: coupon._id,
          status: 'active',
        });

        if (affiliate) {
          affiliateId = affiliate._id;

          const commissionRate = (affiliate.commissionRate || 0) / 100;
          const commissionAmount = Math.round(freshOrder.amount * commissionRate);

          affiliate.balance = (affiliate.balance || 0) + commissionAmount;
          affiliate.totalEarned = (affiliate.totalEarned || 0) + commissionAmount;

          await affiliate.save();

          console.log(
            `[Afiliado] COMISSÃO REGISTRADA! Afiliado: ${affiliate.fullName}. Valor: R$ ${(
              commissionAmount / 100
            ).toFixed(2)}`
          );
        } else {
          console.log(`[Afiliado] Cupom ${freshOrder.couponApplied} não pertence a afiliado ativo.`);
        }
      }
    }

    // Salva ID do afiliado no pedido
    freshOrder.commissionPaidTo = affiliateId;

    // ===============================
    // SALVAR ALTERAÇÕES
    // ===============================
    await product.save();
    await freshOrder.save();

    console.log(
      `[DB] Pedido ${freshOrder.id} atualizado para PAGO. Chave ${assignedKeyStock.key} entregue (pronta para resgate).`
    );

    return true;
  } catch (error) {
    console.error(`[Entrega] Erro CRÍTICO ao processar entrega para o pedido ${order?._id}:`, error);

    // tenta marcar como pago com erro, sem derrubar processo
    try {
      if (order?._id) {
        const safeOrder = await Order.findById(order._id);
        if (safeOrder) {
          safeOrder.status = 'paid';
          safeOrder.assignedKey = 'ERRO_NA_ENTREGA_VERIFICAR_LOGS';
          await safeOrder.save();
        }
      }
    } catch (saveError) {
      console.error(`[Entrega] Falha ao salvar pedido com erro:`, saveError);
    }

    return false;
  }
}

//-- Revisado!

// ==================================================
// WEBHOOK PIX (BLINDADO)
// ==================================================
app.post('/webhook/pix', async (req, res) => {
  try {
    console.log('[WEBHOOK] Notificação PIX recebida');

    const pixArray = req.body?.pix;
    if (!Array.isArray(pixArray) || !pixArray[0]?.txid) {
      return res.status(200).send('OK'); // webhook SEMPRE responde OK
    }

    const txid = pixArray[0].txid;
    console.log(`[WEBHOOK] Processando TXID: ${txid}`);

    if (!efiReady || !efi) {
      console.warn('[WEBHOOK] EFI indisponível, ignorando webhook');
      return res.status(200).send('OK');
    }

    const charge = await efi.pixDetailCharge({ txid });

    if (charge?.status === 'CONCLUIDA') {
      console.log(`[WEBHOOK] Pagamento ${txid} CONCLUÍDO`);

      const order = await Order.findOne({ txid, status: 'pending' });
      if (order) {
        await processAndDeliverOrder(order);
      } else {
        console.log(`[WEBHOOK] Pedido ${txid} já processado ou inexistente`);
      }
    }

    return res.status(200).send('OK');
  } catch (error) {
    console.error(
      '[WEBHOOK] Erro:',
      error?.response?.data || error?.message || error
    );
    return res.status(200).send('OK'); // NUNCA retornar 500 em webhook
  }
});

// ==================================================
// ROTAS PÚBLICAS — CATEGORIAS
// ==================================================
app.get('/api/public/categories', async (req, res) => {
  try {
    const categories = await Category.find().sort({ name: 1 }).lean();
    return res.json(categories);
  } catch (err) {
    console.error('Erro categorias públicas:', err);
    return res.status(500).json({ message: 'Erro interno.' });
  }
});

// ==================================================
// ROTAS PÚBLICAS — PRODUTOS
// ==================================================
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find()
      .select('name slug category imageUrls plans rating isDetectado')
      .populate('category', 'name slug')
      .lean();

    return res.json(products);
  } catch (err) {
    console.error('Erro /api/products:', err);
    return res.status(500).json({ message: 'Erro interno.' });
  }
});

app.get('/api/products/slug/:slug', async (req, res) => {
  try {
    const product = await Product.findOne({ slug: req.params.slug })
      .populate('category')
      .lean();

    if (!product) {
      return res.status(404).json({ message: 'Produto não encontrado' });
    }

    return res.json(product);
  } catch (err) {
    console.error('Erro produto slug:', err);
    return res.status(500).json({ message: 'Erro interno.' });
  }
});

app.get('/api/products/id/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id)
      .populate('category')
      .lean();

    if (!product) {
      return res.status(404).json({ message: 'Produto não encontrado' });
    }

    return res.json(product);
  } catch (err) {
    console.error('Erro produto id:', err);
    return res.status(500).json({ message: 'Erro interno.' });
  }
});

// ==================================================
// AUTH API (ADMIN — BLINDADO)
// ==================================================
function requireAuthApi(req, res, next) {
  try {
    if (typeof req.isAuthenticated === 'function' && req.isAuthenticated() && req.user) {
      return next();
    }
    return res.status(401).json({ message: 'Não autorizado' });
  } catch {
    return res.status(401).json({ message: 'Não autorizado' });
  }
}

function isAdminApi(req, res, next) {
  if (req.user?.role === 'admin') return next();
  return res.status(403).json({ message: 'Acesso negado' });
}

// ==================================================
// ROTAS ADMIN — PRODUTOS
// ==================================================
app.get('/api/admin/products', requireAuthApi, isAdminApi, async (req, res) => {
  try {
    const products = await Product.find()
      .populate('category', 'name')
      .lean();

    return res.json(products);
  } catch (err) {
    console.error('Erro admin products:', err);
    return res.status(500).json({ message: 'Erro interno.' });
  }
});

app.post('/api/admin/products', requireAuthApi, isAdminApi, async (req, res) => {
  try {
    const newProduct = new Product(req.body);
    await newProduct.save();
    return res.status(201).json(newProduct);
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({
        message: 'Já existe um produto com este slug.',
      });
    }
    return res.status(400).json({ message: err.message });
  }
});

app.put('/api/admin/products/:id', requireAuthApi, isAdminApi, async (req, res) => {
  try {
    const product = await Product.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );

    if (!product) {
      return res.status(404).json({ message: 'Produto não encontrado' });
    }

    return res.json(product);
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({
        message: 'Já existe um produto com este slug.',
      });
    }
    return res.status(400).json({ message: err.message });
  }
});

app.delete('/api/admin/products/:id', requireAuthApi, isAdminApi, async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
    if (!product) {
      return res.status(404).json({ message: 'Produto não encontrado' });
    }
    return res.json({ message: 'Produto deletado com sucesso' });
  } catch (err) {
    console.error('Erro delete product:', err);
    return res.status(500).json({ message: 'Erro interno.' });
  }
});

//-- Revisado!

// ==================================================
// AUTH API — BLINDADO (NUNCA QUEBRA OPTIONS)
// ==================================================
function requireAuthApi(req, res, next) {
  try {
    if (typeof req.isAuthenticated === 'function' && req.isAuthenticated() && req.user) {
      return next();
    }
    return res.status(401).json({ message: 'Não autenticado' });
  } catch (err) {
    console.error('[AUTH API] Erro:', err);
    return res.status(401).json({ message: 'Não autenticado' });
  }
}

function isAdminApi(req, res, next) {
  try {
    if (req.user && req.user.role === 'admin') {
      return next();
    }
    return res.status(403).json({ message: 'Acesso negado' });
  } catch (err) {
    console.error('[ADMIN API] Erro:', err);
    return res.status(403).json({ message: 'Acesso negado' });
  }
}

// ==================================================
// CATEGORIAS — ADMIN API
// ==================================================
app.get('/api/admin/categories', requireAuthApi, isAdminApi, async (req, res) => {
  try {
    const categories = await Category.find().sort({ name: 1 }).lean();
    return res.json(categories);
  } catch (err) {
    console.error('[API][CATEGORIES][GET]', err);
    return res.status(500).json({ message: 'Erro ao buscar categorias' });
  }
});

app.post('/api/admin/categories', requireAuthApi, isAdminApi, async (req, res) => {
  try {
    if (!req.body?.name) {
      return res.status(400).json({ message: 'Nome da categoria é obrigatório.' });
    }

    const newCategory = new Category({ name: req.body.name });
    await newCategory.save();

    return res.status(201).json(newCategory);
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({ message: 'Categoria já existe.' });
    }
    return res.status(400).json({ message: err.message });
  }
});

app.put('/api/admin/categories/:id', requireAuthApi, isAdminApi, async (req, res) => {
  try {
    if (!req.body?.name) {
      return res.status(400).json({ message: 'Nome da categoria é obrigatório.' });
    }

    const category = await Category.findByIdAndUpdate(
      req.params.id,
      { name: req.body.name },
      { new: true, runValidators: true }
    );

    if (!category) {
      return res.status(404).json({ message: 'Categoria não encontrada' });
    }

    return res.json(category);
  } catch (err) {
    return res.status(400).json({ message: err.message });
  }
});

app.delete('/api/admin/categories/:id', requireAuthApi, isAdminApi, async (req, res) => {
  try {
    const productCount = await Product.countDocuments({ category: req.params.id });

    if (productCount > 0) {
      return res.status(400).json({
        message: `Existem ${productCount} produto(s) usando esta categoria.`,
      });
    }

    const category = await Category.findByIdAndDelete(req.params.id);
    if (!category) {
      return res.status(404).json({ message: 'Categoria não encontrada' });
    }

    return res.json({ message: 'Categoria deletada com sucesso' });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

// ==================================================
// CUPONS — ADMIN API (PADRONIZADO)
// ==================================================
app.get('/api/admin/coupons', requireAuthApi, isAdminApi, async (req, res) => {
  try {
    const coupons = await Coupon.find().sort({ createdAt: -1 }).lean();
    return res.json(coupons);
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

app.get('/api/admin/coupons/:id', requireAuthApi, isAdminApi, async (req, res) => {
  try {
    const coupon = await Coupon.findById(req.params.id).lean();
    if (!coupon) {
      return res.status(404).json({ message: 'Cupom não encontrado' });
    }
    return res.json(coupon);
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

app.post('/api/admin/coupons', requireAuthApi, isAdminApi, async (req, res) => {
  try {
    if (!req.body.maxUses) req.body.maxUses = null;
    if (!req.body.expiresAt) req.body.expiresAt = null;

    const newCoupon = new Coupon(req.body);
    await newCoupon.save();

    return res.status(201).json(newCoupon);
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({
        message: 'Já existe um cupom com este código.',
      });
    }
    return res.status(400).json({ message: err.message });
  }
});

app.put('/api/admin/coupons/:id', requireAuthApi, isAdminApi, async (req, res) => {
  try {
    if (!req.body.maxUses) req.body.maxUses = null;
    if (!req.body.expiresAt) req.body.expiresAt = null;

    const coupon = await Coupon.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
    });

    if (!coupon) {
      return res.status(404).json({ message: 'Cupom não encontrado' });
    }

    return res.json(coupon);
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({
        message: 'Já existe um cupom com este código.',
      });
    }
    return res.status(400).json({ message: err.message });
  }
});

app.delete('/api/admin/coupons/:id', requireAuthApi, isAdminApi, async (req, res) => {
  try {
    const coupon = await Coupon.findByIdAndDelete(req.params.id);
    if (!coupon) {
      return res.status(404).json({ message: 'Cupom não encontrado' });
    }
    return res.json({ message: 'Cupom deletado com sucesso' });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

//-- Revisado!

// ==================================================
// AUTH API — BLINDADO
// ==================================================
function requireAuthApi(req, res, next) {
  try {
    if (typeof req.isAuthenticated === 'function' && req.isAuthenticated() && req.user) {
      return next();
    }
    return res.status(401).json({ message: 'Não autenticado' });
  } catch (err) {
    console.error('[AUTH API] Erro:', err);
    return res.status(401).json({ message: 'Não autenticado' });
  }
}

function isAdminApi(req, res, next) {
  try {
    if (req.user?.role === 'admin') return next();
    return res.status(403).json({ message: 'Acesso negado' });
  } catch (err) {
    console.error('[ADMIN API] Erro:', err);
    return res.status(403).json({ message: 'Acesso negado' });
  }
}

// ==================================================
// AFILIADOS — ADMIN API
// ==================================================
app.get('/api/admin/affiliates', requireAuthApi, isAdminApi, async (req, res) => {
  try {
    const affiliates = await Affiliate.find()
      .populate('user', 'username email')
      .populate('linkedCoupons', 'code')
      .sort({ createdAt: -1 })
      .lean();

    return res.json(affiliates);
  } catch (err) {
    console.error('[ADMIN][AFFILIATES][GET]', err);
    return res.status(500).json({ message: 'Erro ao buscar afiliados' });
  }
});

app.get('/api/admin/affiliates/:id', requireAuthApi, isAdminApi, async (req, res) => {
  try {
    const affiliate = await Affiliate.findById(req.params.id)
      .populate('user', 'username email')
      .populate('linkedCoupons', '_id')
      .lean();

    if (!affiliate) {
      return res.status(404).json({ message: 'Afiliado não encontrado' });
    }

    return res.json(affiliate);
  } catch (err) {
    return res.status(500).json({ message: 'Erro ao buscar afiliado' });
  }
});

app.post('/api/admin/affiliates', requireAuthApi, isAdminApi, async (req, res) => {
  try {
    const { username, fullName, paymentDetails, ...rest } = req.body || {};

    if (!username || !fullName) {
      return res.status(400).json({ message: 'Username e nome completo são obrigatórios.' });
    }

    const user = await User.findOne({ username }).lean();
    if (!user) {
      return res.status(404).json({
        message: `Usuário '${username}' não encontrado.`,
      });
    }

    const existingAffiliate = await Affiliate.findOne({ user: user._id });
    if (existingAffiliate) {
      return res.status(400).json({
        message: 'Este usuário já está cadastrado como afiliado.',
      });
    }

    const newAffiliate = new Affiliate({
      ...rest,
      user: user._id,
      fullName,
      paymentDetails,
    });

    await newAffiliate.save();
    return res.status(201).json(newAffiliate);
  } catch (err) {
    console.error('[ADMIN][AFFILIATES][POST]', err);
    if (err.name === 'ValidationError') {
      return res.status(400).json({ message: err.message });
    }
    return res.status(400).json({ message: 'Erro ao criar afiliado' });
  }
});

app.put('/api/admin/affiliates/:id', requireAuthApi, isAdminApi, async (req, res) => {
  try {
    const { username, user, ...updateData } = req.body || {};

    const affiliate = await Affiliate.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true, runValidators: true }
    );

    if (!affiliate) {
      return res.status(404).json({ message: 'Afiliado não encontrado' });
    }

    return res.json(affiliate);
  } catch (err) {
    if (err.name === 'ValidationError') {
      return res.status(400).json({ message: err.message });
    }
    return res.status(400).json({ message: 'Erro ao atualizar afiliado' });
  }
});

app.delete('/api/admin/affiliates/:id', requireAuthApi, isAdminApi, async (req, res) => {
  try {
    const affiliate = await Affiliate.findByIdAndDelete(req.params.id);
    if (!affiliate) {
      return res.status(404).json({ message: 'Afiliado não encontrado' });
    }
    return res.json({ message: 'Afiliado deletado com sucesso' });
  } catch (err) {
    return res.status(500).json({ message: 'Erro ao deletar afiliado' });
  }
});

// ==================================================
// DASHBOARD — ADMIN API
// ==================================================
app.get('/api/admin/dashboard-stats', requireAuthApi, isAdminApi, async (req, res) => {
  try {
    const { start, end } = req.query || {};

    const dateFilter = {};
    if (start) dateFilter.$gte = new Date(new Date(start).setHours(0, 0, 0, 0));
    if (end) dateFilter.$lte = new Date(new Date(end).setHours(23, 59, 59, 999));

    const hasDateFilter = Object.keys(dateFilter).length > 0;

    const [
      totalSales,
      filteredSales,
      couponsUsed,
      newUsers,
      recentOrders,
    ] = await Promise.all([
      Order.aggregate([
        { $match: { status: 'paid' } },
        { $group: { _id: null, total: { $sum: '$amount' } } },
      ]),
      Order.aggregate([
        {
          $match: {
            status: 'paid',
            ...(hasDateFilter && { createdAt: dateFilter }),
          },
        },
        { $group: { _id: null, total: { $sum: '$amount' } } },
      ]),
      Order.countDocuments({
        status: 'paid',
        couponApplied: { $ne: null },
        ...(hasDateFilter && { createdAt: dateFilter }),
      }),
      User.countDocuments({
        ...(hasDateFilter && { createdAt: dateFilter }),
      }),
      Order.find({ status: 'paid' })
        .sort({ createdAt: -1 })
        .limit(10)
        .populate('user', 'username')
        .lean(),
    ]);

    return res.json({
      totalSales: totalSales[0]?.total || 0,
      filteredSales: filteredSales[0]?.total || 0,
      couponsUsed: couponsUsed || 0,
      newUsers: newUsers || 0,
      recentOrders: recentOrders || [],
    });
  } catch (error) {
    console.error('[ADMIN][DASHBOARD]', error);
    return res.status(500).json({ message: 'Erro interno do servidor.' });
  }
});

//-- Revisado!

// ==================================================
// SAQUES — ADMIN API
// ==================================================
app.get('/api/admin/withdrawals', requireAuthApi, isAdminApi, async (req, res) => {
  try {
    const affiliates = await Affiliate.find({
      'withdrawals.0': { $exists: true },
    })
      .populate('user', 'username')
      .lean();

    const allWithdrawals = [];

    for (const affiliate of affiliates) {
      if (!Array.isArray(affiliate.withdrawals)) continue;

      for (const w of affiliate.withdrawals) {
        allWithdrawals.push({
          ...w,
          affiliate: {
            _id: affiliate._id,
            fullName: affiliate.fullName,
            user: affiliate.user,
          },
        });
      }
    }

    allWithdrawals.sort(
      (a, b) => new Date(b.createdAt) - new Date(a.createdAt)
    );

    return res.json(allWithdrawals);
  } catch (err) {
    console.error('[ADMIN][WITHDRAWALS][GET]', err);
    return res.status(500).json({ message: 'Erro ao buscar saques.' });
  }
});

// ==================================================
// ATUALIZAR STATUS DO SAQUE — ADMIN API
// ==================================================
app.put(
  '/api/admin/withdrawals/:id/status',
  requireAuthApi,
  isAdminApi,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status, reason } = req.body || {};

      if (!status) {
        return res.status(400).json({ message: 'Status é obrigatório.' });
      }

      const affiliate = await Affiliate.findOne({
        'withdrawals._id': id,
      });

      if (!affiliate) {
        return res
          .status(404)
          .json({ message: 'Solicitação de saque não encontrada.' });
      }

      const withdrawal = affiliate.withdrawals.id(id);
      if (!withdrawal) {
        return res
          .status(404)
          .json({ message: 'Subdocumento de saque não encontrado.' });
      }

      const oldStatus = withdrawal.status;

      // ===============================
      // LÓGICA DE TRANSIÇÃO DE STATUS
      // ===============================
      if (status === 'approved' && oldStatus === 'pending') {
        withdrawal.status = 'approved';
      } 
      else if (status === 'completed' && oldStatus === 'approved') {
        withdrawal.status = 'completed';
      } 
      else if (
        status === 'rejected' &&
        (oldStatus === 'pending' || oldStatus === 'approved')
      ) {
        if (!reason) {
          return res
            .status(400)
            .json({ message: 'O motivo da recusa é obrigatório.' });
        }

        affiliate.balance += withdrawal.amount;
        affiliate.totalWithdrawn -= withdrawal.amount;

        withdrawal.status = 'rejected';
        withdrawal.rejectionReason = reason;
      } 
      else {
        return res.status(400).json({
          message: `Não é possível mudar o status de '${oldStatus}' para '${status}'.`,
        });
      }

      await affiliate.save();

      return res.json({
        message: `Saque atualizado para '${status}'.`,
        withdrawal,
      });
    } catch (err) {
      console.error('[ADMIN][WITHDRAWALS][PUT]', err);

      if (err.name === 'ValidationError') {
        return res.status(400).json({ message: err.message });
      }

      return res
        .status(500)
        .json({ message: 'Erro interno do servidor.' });
    }
  }
);

//-- Revisado!

// ==================================================
// AUTH API — AFILIADO (BLINDADO)
// ==================================================
function requireAffiliateApi(req, res, next) {
  try {
    if (
      typeof req.isAuthenticated === 'function' &&
      req.isAuthenticated() &&
      req.affiliate
    ) {
      return next();
    }
    return res.status(401).json({ message: 'Não autorizado' });
  } catch (err) {
    console.error('[AFFILIATE AUTH] Erro:', err);
    return res.status(401).json({ message: 'Não autorizado' });
  }
}

// ==================================================
// DASHBOARD DO AFILIADO
// ==================================================
app.get('/api/affiliate/dashboard', requireAffiliateApi, async (req, res) => {
  try {
    const affiliate = req.affiliate;

    // populate seguro
    if (typeof affiliate.populate === 'function') {
      await affiliate.populate('linkedCoupons');
    }

    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

    const [salesLast30Days, recentSales] = await Promise.all([
      Order.countDocuments({
        commissionPaidTo: affiliate._id,
        createdAt: { $gte: thirtyDaysAgo },
      }),
      Order.find({ commissionPaidTo: affiliate._id })
        .sort({ createdAt: -1 })
        .limit(5)
        .select('createdAt productTitle productPlan amount')
        .lean(),
    ]);

    return res.json({
      balance: affiliate.balance || 0,
      totalEarned: affiliate.totalEarned || 0,
      totalWithdrawn: affiliate.totalWithdrawn || 0,
      salesLast30Days,
      recentSales,
      myCoupons: affiliate.linkedCoupons || [],
      commissionRate: affiliate.commissionRate || 0,
    });
  } catch (err) {
    console.error('Erro dashboard afiliado:', err);
    return res.status(500).json({ message: 'Erro interno do servidor.' });
  }
});

// ==================================================
// HISTÓRICO DE SAQUES — AFILIADO
// ==================================================
app.get('/api/affiliate/withdrawals', requireAffiliateApi, async (req, res) => {
  try {
    return res.json(req.affiliate.withdrawals || []);
  } catch (err) {
    return res.status(500).json({ message: 'Erro interno do servidor.' });
  }
});

// ==================================================
// SOLICITAR SAQUE — AFILIADO
// ==================================================
app.post('/api/affiliate/request-withdrawal', requireAffiliateApi, async (req, res) => {
  try {
    const affiliate = req.affiliate;
    const minimumWithdrawal = 10000; // R$ 100,00 em centavos

    if (affiliate.balance < minimumWithdrawal) {
      return res.status(400).json({
        message: 'Saldo insuficiente. O mínimo para saque é R$ 100,00.',
      });
    }

    const hasPending = affiliate.withdrawals?.some(
      (w) => w.status === 'pending'
    );
    if (hasPending) {
      return res.status(400).json({
        message: 'Você já possui uma solicitação de saque pendente.',
      });
    }

    const withdrawalAmount = affiliate.balance;

    affiliate.withdrawals.push({
      amount: withdrawalAmount,
      status: 'pending',
      paymentDetailsSnapshot: affiliate.paymentDetails,
    });

    affiliate.balance = 0;
    affiliate.totalWithdrawn += withdrawalAmount;

    await affiliate.save();

    return res
      .status(201)
      .json({ message: 'Solicitação de saque enviada com sucesso!' });
  } catch (err) {
    console.error('Erro solicitar saque:', err);
    return res.status(500).json({ message: 'Erro interno do servidor.' });
  }
});

// ==================================================
// PROTEÇÃO CONTRA CRASH
// ==================================================
process.on('uncaughtException', (err) => {
  console.error('uncaughtException:', err);
});

process.on('unhandledRejection', (err) => {
  console.error('unhandledRejection:', err);
});

console.log('🔥 CHEGOU ANTES DO LISTEN');

const PORT = process.env.PORT || 8080;
console.log('🌐 PORT DO RAILWAY:', process.env.PORT);

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 API escutando na porta ${PORT}`);
});

//-- Revisado!
