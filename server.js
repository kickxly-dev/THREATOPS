'use strict';
require('dotenv').config();

const express = require('express');
const net = require('net');
const dns = require('dns').promises;
const fetch = require('node-fetch');
const whois = require('whois');
const tls = require('tls');
const fs = require('fs').promises;
const fsSync = require('fs');
const crypto = require('crypto');
const { URL } = require('url');
const path = require('path');
const { Pool } = require('pg');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ─── POSTGRES POOL ────────────────────────────────────────────────────────────
const pool = process.env.DATABASE_URL
  ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } })
  : null;

// ─── FILE-BASED STORAGE ───────────────────────────────────────────────────────
const DATA_DIR = path.join(__dirname, 'data');
const HISTORY_DIR = path.join(__dirname, 'history');
fsSync.mkdirSync(DATA_DIR, { recursive: true });
fsSync.mkdirSync(HISTORY_DIR, { recursive: true });
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');

function fileLoadUsers() {
  try { return JSON.parse(fsSync.readFileSync(USERS_FILE, 'utf8')); } catch { return []; }
}
async function fileSaveUsers(users) {
  await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
}

// ─── DB INIT ─────────────────────────────────────────────────────────────────
async function initDB() {
  if (!pool) {
    try {
      const cfg = JSON.parse(fsSync.readFileSync(CONFIG_FILE, 'utf8'));
      for (const [k, v] of Object.entries(cfg)) { if (v) process.env[k] = v; }
    } catch {}
    return;
  }
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(), onboarded BOOLEAN DEFAULT FALSE, is_admin BOOLEAN DEFAULT FALSE
  )`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE`);
  await pool.query(`CREATE TABLE IF NOT EXISTS scan_history (
    id TEXT PRIMARY KEY, ts TIMESTAMPTZ DEFAULT NOW(), user_id TEXT, target TEXT NOT NULL, email TEXT,
    total_findings INT DEFAULT 0, high_count INT DEFAULT 0, medium_count INT DEFAULT 0,
    low_count INT DEFAULT 0, info_count INT DEFAULT 0, results JSONB, findings JSONB, share_token TEXT UNIQUE
  )`);
  await pool.query(`ALTER TABLE scan_history ADD COLUMN IF NOT EXISTS user_id TEXT`);
  await pool.query(`ALTER TABLE scan_history ADD COLUMN IF NOT EXISTS share_token TEXT`);
  await pool.query(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`);
  const { rows } = await pool.query('SELECT key, value FROM settings');
  for (const { key, value } of rows) { if (value) process.env[key] = value; }
}

// ─── DUAL-MODE USER OPS ───────────────────────────────────────────────────────
async function dbFindUser(username) {
  if (!pool) {
    const u = fileLoadUsers().find(u => u.username.toLowerCase() === username.toLowerCase());
    return u || null;
  }
  const { rows } = await pool.query(
    `SELECT id, username, password_hash AS "passwordHash", onboarded, is_admin AS "isAdmin", created_at AS "createdAt"
     FROM users WHERE LOWER(username) = LOWER($1)`, [username]);
  return rows[0] || null;
}

async function dbFindUserById(id) {
  if (!pool) {
    const u = fileLoadUsers().find(u => u.id === id);
    return u || null;
  }
  const { rows } = await pool.query(
    `SELECT id, username, password_hash AS "passwordHash", onboarded, is_admin AS "isAdmin", created_at AS "createdAt"
     FROM users WHERE id = $1`, [id]);
  return rows[0] || null;
}

async function dbCreateUser(user) {
  if (!pool) {
    const users = fileLoadUsers();
    if (users.find(u => u.username.toLowerCase() === user.username.toLowerCase())) return false;
    if (users.length === 0) user.isAdmin = true;
    users.push(user);
    await fileSaveUsers(users);
    return true;
  }
  const { rows: c } = await pool.query('SELECT COUNT(*) FROM users');
  const isFirst = parseInt(c[0].count) === 0;
  if (isFirst) user.isAdmin = true;
  try {
    await pool.query(
      `INSERT INTO users (id, username, password_hash, onboarded, is_admin) VALUES ($1,$2,$3,$4,$5)`,
      [user.id, user.username, user.passwordHash, user.onboarded || false, isFirst]);
    return true;
  } catch (e) { if (e.code === '23505') return false; throw e; }
}

async function dbSetOnboarded(userId) {
  if (!pool) {
    const users = fileLoadUsers();
    const u = users.find(u => u.id === userId);
    if (!u) return false;
    u.onboarded = true;
    await fileSaveUsers(users);
    return true;
  }
  await pool.query('UPDATE users SET onboarded = TRUE WHERE id = $1', [userId]);
  return true;
}

async function dbGetAllUsers() {
  if (!pool) {
    return fileLoadUsers().map(u => ({ id: u.id, username: u.username, createdAt: u.createdAt, isAdmin: u.isAdmin || false, onboarded: u.onboarded }));
  }
  const { rows } = await pool.query(
    `SELECT id, username, created_at AS "createdAt", is_admin AS "isAdmin", onboarded FROM users ORDER BY created_at`);
  return rows;
}

async function dbDeleteUser(userId) {
  if (!pool) {
    // delete their history files
    try {
      const files = (await fs.readdir(HISTORY_DIR)).filter(f => f.endsWith('.json'));
      for (const f of files) {
        try {
          const d = JSON.parse(await fs.readFile(path.join(HISTORY_DIR, f), 'utf8'));
          if (d.userId === userId) await fs.unlink(path.join(HISTORY_DIR, f));
        } catch {}
      }
    } catch {}
    const users = fileLoadUsers().filter(u => u.id !== userId);
    await fileSaveUsers(users);
    return;
  }
  await pool.query('DELETE FROM scan_history WHERE user_id = $1', [userId]);
  await pool.query('DELETE FROM users WHERE id = $1', [userId]);
}

// ─── DUAL-MODE SETTINGS ───────────────────────────────────────────────────────
async function dbSaveSettings(updates) {
  if (!pool) {
    let cfg = {};
    try { cfg = JSON.parse(await fs.readFile(CONFIG_FILE, 'utf8')); } catch {}
    Object.assign(cfg, updates);
    await fs.writeFile(CONFIG_FILE, JSON.stringify(cfg, null, 2));
    return;
  }
  for (const [key, value] of Object.entries(updates)) {
    await pool.query(`INSERT INTO settings (key,value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=$2`, [key, value]);
  }
}

// ─── DUAL-MODE HISTORY ────────────────────────────────────────────────────────
async function dbSaveHistory(id, userId, target, email, results, findings) {
  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  if (!pool) {
    try {
      await fs.writeFile(path.join(HISTORY_DIR, `${id}.json`),
        JSON.stringify({ id, ts: new Date().toISOString(), userId, target, email: email || null, total: findings.length, ...counts, results, findings }));
    } catch {}
    return;
  }
  try {
    await pool.query(
      `INSERT INTO scan_history (id,user_id,target,email,total_findings,high_count,medium_count,low_count,info_count,results,findings)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [id, userId, target, email || null, findings.length, counts.high, counts.medium, counts.low, counts.info, JSON.stringify(results), JSON.stringify(findings)]);
  } catch {}
}

async function dbGetHistory(userId, isAdmin) {
  if (!pool) {
    try {
      const files = (await fs.readdir(HISTORY_DIR)).filter(f => f.endsWith('.json')).sort().reverse().slice(0, 100);
      const items = await Promise.allSettled(files.map(async f => {
        const d = JSON.parse(await fs.readFile(path.join(HISTORY_DIR, f), 'utf8'));
        if (!isAdmin && d.userId && d.userId !== userId) return null;
        return { id: d.id, ts: d.ts, target: d.target, total: d.total, high: d.high, medium: d.medium, low: d.low, info: d.info, userId: d.userId };
      }));
      return items.filter(r => r.status === 'fulfilled' && r.value).map(r => r.value);
    } catch { return []; }
  }
  const q = isAdmin
    ? `SELECT id,ts,user_id AS "userId",target,total_findings AS total,high_count AS high,medium_count AS medium,low_count AS low,info_count AS info FROM scan_history ORDER BY ts DESC LIMIT 100`
    : `SELECT id,ts,user_id AS "userId",target,total_findings AS total,high_count AS high,medium_count AS medium,low_count AS low,info_count AS info FROM scan_history WHERE user_id=$1 OR user_id IS NULL ORDER BY ts DESC LIMIT 100`;
  const { rows } = await pool.query(q, isAdmin ? [] : [userId]);
  return rows;
}

async function dbGetHistoryItem(id, userId, isAdmin) {
  if (!pool) {
    const safe = id.replace(/[^a-z0-9]/gi, '');
    const d = JSON.parse(await fs.readFile(path.join(HISTORY_DIR, `${safe}.json`), 'utf8'));
    if (!isAdmin && d.userId && d.userId !== userId) throw new Error('Not found');
    return d;
  }
  const q = isAdmin
    ? `SELECT * FROM scan_history WHERE id=$1`
    : `SELECT * FROM scan_history WHERE id=$1 AND (user_id=$2 OR user_id IS NULL)`;
  const { rows } = await pool.query(q, isAdmin ? [id] : [id, userId]);
  if (!rows[0]) throw new Error('Not found');
  const r = rows[0];
  return { id: r.id, ts: r.ts, userId: r.user_id, target: r.target, email: r.email, total: r.total_findings, high: r.high_count, medium: r.medium_count, low: r.low_count, info: r.info_count, results: r.results, findings: r.findings, shareToken: r.share_token };
}

async function dbDeleteHistory(id, userId, isAdmin) {
  if (!pool) {
    const safe = id.replace(/[^a-z0-9]/gi, '');
    const fPath = path.join(HISTORY_DIR, `${safe}.json`);
    const d = JSON.parse(await fs.readFile(fPath, 'utf8'));
    if (!isAdmin && d.userId && d.userId !== userId) throw new Error('Not found');
    await fs.unlink(fPath);
    return;
  }
  const q = isAdmin
    ? `DELETE FROM scan_history WHERE id=$1`
    : `DELETE FROM scan_history WHERE id=$1 AND (user_id=$2 OR user_id IS NULL)`;
  const { rowCount } = await pool.query(q, isAdmin ? [id] : [id, userId]);
  if (!rowCount) throw new Error('Not found');
}

async function dbGenerateShareToken(id, userId, isAdmin) {
  const token = crypto.randomBytes(20).toString('hex');
  if (!pool) {
    const safe = id.replace(/[^a-z0-9]/gi, '');
    const fPath = path.join(HISTORY_DIR, `${safe}.json`);
    const d = JSON.parse(await fs.readFile(fPath, 'utf8'));
    if (!isAdmin && d.userId && d.userId !== userId) throw new Error('Not found');
    d.shareToken = token;
    await fs.writeFile(fPath, JSON.stringify(d));
    return token;
  }
  const q = isAdmin
    ? `UPDATE scan_history SET share_token=$1 WHERE id=$2 RETURNING id`
    : `UPDATE scan_history SET share_token=$1 WHERE id=$2 AND (user_id=$3 OR user_id IS NULL) RETURNING id`;
  const { rows } = await pool.query(q, isAdmin ? [token, id] : [token, id, userId]);
  if (!rows.length) throw new Error('Not found');
  return token;
}

async function dbGetHistoryByToken(token) {
  if (!pool) {
    const files = await fs.readdir(HISTORY_DIR).catch(() => []);
    for (const f of files.filter(f => f.endsWith('.json'))) {
      try {
        const d = JSON.parse(await fs.readFile(path.join(HISTORY_DIR, f), 'utf8'));
        if (d.shareToken === token) return d;
      } catch {}
    }
    throw new Error('Not found');
  }
  const { rows } = await pool.query('SELECT * FROM scan_history WHERE share_token=$1', [token]);
  if (!rows[0]) throw new Error('Not found');
  const r = rows[0];
  return { id: r.id, ts: r.ts, target: r.target, email: r.email, total: r.total_findings, high: r.high_count, medium: r.medium_count, low: r.low_count, info: r.info_count, results: r.results, findings: r.findings };
}

// ─── PASSWORD UTILS ───────────────────────────────────────────────────────────
async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = await new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, d) => err ? reject(err) : resolve(d.toString('hex')));
  });
  return `${salt}:${hash}`;
}

async function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  return new Promise((resolve) => {
    crypto.scrypt(password, salt, 64, (err, d) => {
      if (err) return resolve(false);
      try { resolve(crypto.timingSafeEqual(Buffer.from(hash, 'hex'), d)); } catch { resolve(false); }
    });
  });
}

// ─── SESSIONS ────────────────────────────────────────────────────────────────
const sessions = new Map();

function parseCookies(header) {
  const c = {}; if (!header) return c;
  for (const p of header.split(';')) { const [k, ...v] = p.trim().split('='); c[k.trim()] = v.join('=').trim(); }
  return c;
}

function createSession(userId, username, isAdmin = false) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { userId, username, isAdmin, expiry: Date.now() + 24 * 60 * 60 * 1000 });
  return token;
}

function getSession(req) {
  const token = parseCookies(req.headers.cookie)['to_session'];
  if (!token) return null;
  const s = sessions.get(token);
  if (!s || Date.now() > s.expiry) { sessions.delete(token); return null; }
  return s;
}

setInterval(() => { const now = Date.now(); for (const [t, s] of sessions) if (now > s.expiry) sessions.delete(t); }, 60 * 60 * 1000);

// ─── RATE LIMITER ────────────────────────────────────────────────────────────
const rateLimits = new Map();
const RATE_LIMIT = parseInt(process.env.RATE_LIMIT || '10');
function rateLimit(req, res, next) {
  const ip = req.ip || 'unknown';
  const now = Date.now();
  const r = rateLimits.get(ip);
  if (!r || now > r.resetAt) { rateLimits.set(ip, { count: 1, resetAt: now + 60000 }); return next(); }
  if (r.count >= RATE_LIMIT) return res.status(429).json({ error: `Rate limit exceeded. Retry in ${Math.ceil((r.resetAt - now) / 1000)}s` });
  r.count++;
  next();
}
setInterval(() => { const now = Date.now(); for (const [ip, r] of rateLimits) if (now > r.resetAt) rateLimits.delete(ip); }, 5 * 60 * 1000);

// ─── SCAN QUEUE ──────────────────────────────────────────────────────────────
const MAX_CONCURRENT_SCANS = parseInt(process.env.MAX_SCANS || '3');
let activeScans = 0;
const scanQueue = [];

function acquireScanSlot() {
  return new Promise((resolve) => {
    if (activeScans < MAX_CONCURRENT_SCANS) { activeScans++; resolve(); }
    else scanQueue.push(resolve);
  });
}

function releaseScanSlot() {
  if (scanQueue.length > 0) { const next = scanQueue.shift(); next(); }
  else activeScans--;
}

// ─── AUTH MIDDLEWARE ─────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  req.user = getSession(req);
  if (req.user) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' });
  res.redirect('/login');
}

function requireAdmin(req, res, next) {
  req.user = getSession(req);
  if (!req.user) {
    if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' });
    return res.redirect('/login');
  }
  if (!req.user.isAdmin) {
    if (req.path.startsWith('/api/')) return res.status(403).json({ error: 'Forbidden' });
    return res.status(403).send('Access denied');
  }
  next();
}

// ─── LOGIN PAGE ──────────────────────────────────────────────────────────────
const loginPage = (opts = {}) => `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>THREATOPS // ACCESS</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Share+Tech+Mono&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#050507;color:#e0e0e8;font-family:'JetBrains Mono',monospace;min-height:100vh;display:flex;align-items:center;justify-content:center;background-image:radial-gradient(circle at 20% 50%, rgba(255,42,42,0.04) 0%, transparent 50%), radial-gradient(circle at 80% 20%, rgba(0,200,255,0.03) 0%, transparent 50%)}
.wrap{width:100%;max-width:420px;padding:20px}
.logo{font-family:'Share Tech Mono',monospace;font-size:22px;color:#ff2a2a;letter-spacing:4px;margin-bottom:4px}
.tagline{font-size:10px;color:#444458;letter-spacing:1px;margin-bottom:32px}
.card{background:#0a0a0e;border:1px solid #1a1a24;border-top:2px solid #ff2a2a;padding:28px}
.tabs{display:flex;margin-bottom:24px;border-bottom:1px solid #1a1a24}
.tab{flex:1;text-align:center;padding:8px;font-size:10px;font-weight:700;letter-spacing:1px;text-transform:uppercase;cursor:pointer;color:#444458;border-bottom:2px solid transparent;transition:all .15s}
.tab.active{color:#ff2a2a;border-bottom-color:#ff2a2a}
.field{margin-bottom:14px}
label{display:block;font-size:9.5px;color:#8888a0;letter-spacing:1px;text-transform:uppercase;margin-bottom:5px}
input{width:100%;padding:9px 10px;background:#0f0f14;border:1px solid #1a1a24;color:#e0e0e8;font-family:'JetBrains Mono',monospace;font-size:12px;outline:none;transition:border-color .15s}
input:focus{border-color:#00c8ff}
input::placeholder{color:#444458}
.hint{font-size:9px;color:#444458;margin-top:3px}
.btn{width:100%;padding:10px;background:#ff2a2a;border:none;color:#fff;font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:700;letter-spacing:1.5px;cursor:pointer;text-transform:uppercase;transition:background .15s;margin-top:4px}
.btn:hover{background:#ff4444;box-shadow:0 0 14px rgba(255,42,42,.3)}
.err{color:#ff6b6b;font-size:10px;margin-top:10px;padding:7px 9px;background:rgba(255,42,42,.08);border-left:3px solid #ff2a2a}
.ok{color:#00e676;font-size:10px;margin-top:10px;padding:7px 9px;background:rgba(0,230,118,.08);border-left:3px solid #00e676}
.form-section{display:none}.form-section.active{display:block}
</style>
</head>
<body>
<div class="wrap">
  <div class="logo">⚔ THREATOPS</div>
  <div class="tagline">THREAT INTELLIGENCE PLATFORM</div>
  <div class="card">
    <div class="tabs">
      <div class="tab ${opts.tab !== 'register' ? 'active' : ''}" onclick="switchTab('login')">Sign In</div>
      <div class="tab ${opts.tab === 'register' ? 'active' : ''}" onclick="switchTab('register')">Create Account</div>
    </div>
    <div class="form-section ${opts.tab !== 'register' ? 'active' : ''}" id="login-form">
      <form method="POST" action="/api/login">
        <div class="field"><label>Username</label><input type="text" name="username" autocomplete="username" required autofocus></div>
        <div class="field"><label>Password</label><input type="password" name="password" autocomplete="current-password" required></div>
        <button class="btn" type="submit">Authenticate</button>
        ${opts.loginErr ? `<div class="err">${opts.loginErr}</div>` : ''}
      </form>
    </div>
    <div class="form-section ${opts.tab === 'register' ? 'active' : ''}" id="register-form">
      <form method="POST" action="/api/register">
        <div class="field"><label>Username</label><input type="text" name="username" autocomplete="username" pattern="[a-zA-Z0-9_]{3,20}" required><div class="hint">3–20 chars, letters/numbers/underscore</div></div>
        <div class="field"><label>Password</label><input type="password" name="password" autocomplete="new-password" minlength="8" required><div class="hint">Minimum 8 characters</div></div>
        <div class="field"><label>Confirm Password</label><input type="password" name="confirm" autocomplete="new-password" required></div>
        <button class="btn" type="submit">Create Account</button>
        ${opts.registerErr ? `<div class="err">${opts.registerErr}</div>` : ''}
        ${opts.registerOk ? `<div class="ok">${opts.registerOk}</div>` : ''}
      </form>
    </div>
  </div>
</div>
<script>
function switchTab(t) {
  document.querySelectorAll('.tab').forEach((el,i)=>el.classList.toggle('active',(t==='login'&&i===0)||(t==='register'&&i===1)));
  document.querySelectorAll('.form-section').forEach((el,i)=>el.classList.toggle('active',(t==='login'&&i===0)||(t==='register'&&i===1)));
}
${opts.autoTab ? `switchTab('${opts.autoTab}');` : ''}
</script>
</body></html>`;

// ─── AUTH ROUTES ─────────────────────────────────────────────────────────────
app.get('/login', (req, res) => {
  if (getSession(req)) return res.redirect('/');
  res.send(loginPage({ tab: req.query.tab }));
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.send(loginPage({ loginErr: 'Username and password required.' }));
  let user;
  try { user = await dbFindUser(username); }
  catch (err) { console.error('Login error:', err); return res.send(loginPage({ loginErr: 'Server error. Please try again.' })); }
  if (!user || !(await verifyPassword(password, user.passwordHash))) {
    return res.send(loginPage({ loginErr: 'Invalid username or password.' }));
  }
  const token = createSession(user.id, user.username, user.isAdmin || false);
  res.setHeader('Set-Cookie', `to_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400`);
  res.redirect('/');
});

app.post('/api/register', async (req, res) => {
  const { username, password, confirm } = req.body;
  if (!username || !password || !confirm)
    return res.send(loginPage({ tab: 'register', registerErr: 'All fields required.' }));
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username))
    return res.send(loginPage({ tab: 'register', registerErr: 'Username must be 3–20 alphanumeric characters.' }));
  if (password.length < 8)
    return res.send(loginPage({ tab: 'register', registerErr: 'Password must be at least 8 characters.' }));
  if (password !== confirm)
    return res.send(loginPage({ tab: 'register', registerErr: 'Passwords do not match.' }));
  const newUser = { id: crypto.randomBytes(8).toString('hex'), username, passwordHash: await hashPassword(password), createdAt: new Date().toISOString(), onboarded: false, isAdmin: false };
  let created;
  try { created = await dbCreateUser(newUser); }
  catch (err) { console.error('Register error:', err); return res.send(loginPage({ tab: 'register', registerErr: 'Server error during registration. Please try again.' })); }
  if (!created) return res.send(loginPage({ tab: 'register', registerErr: 'Username already taken.' }));
  const token = createSession(newUser.id, newUser.username, newUser.isAdmin || false);
  res.setHeader('Set-Cookie', `to_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400`);
  res.redirect('/');
});

app.get('/api/logout', (req, res) => {
  const token = parseCookies(req.headers.cookie)['to_session'];
  if (token) sessions.delete(token);
  res.setHeader('Set-Cookie', 'to_session=; Max-Age=0; Path=/');
  res.redirect('/login');
});

app.get('/api/me', requireAuth, async (req, res) => {
  const user = await dbFindUserById(req.user.userId).catch(() => null);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, username: user.username, onboarded: user.onboarded, isAdmin: user.isAdmin || false, createdAt: user.createdAt });
});

app.post('/api/onboarding/complete', requireAuth, async (req, res) => {
  await dbSetOnboarded(req.user.userId).catch(() => {});
  res.json({ ok: true });
});

// ─── SETTINGS ────────────────────────────────────────────────────────────────
app.get('/api/settings', requireAuth, (req, res) => {
  res.json({
    HIBP_API_KEY: process.env.HIBP_API_KEY ? '••••••••' : '',
    ABUSEIPDB_API_KEY: process.env.ABUSEIPDB_API_KEY ? '••••••••' : '',
    SHODAN_API_KEY: process.env.SHODAN_API_KEY ? '••••••••' : '',
    hibpConfigured: !!(process.env.HIBP_API_KEY && process.env.HIBP_API_KEY !== 'your_hibp_key_here'),
    abuseConfigured: !!(process.env.ABUSEIPDB_API_KEY && process.env.ABUSEIPDB_API_KEY !== 'your_abuseipdb_key_here'),
    shodanConfigured: !!(process.env.SHODAN_API_KEY && process.env.SHODAN_API_KEY !== 'your_shodan_key_here'),
  });
});

app.post('/api/settings', requireAuth, async (req, res) => {
  const allowed = ['HIBP_API_KEY', 'ABUSEIPDB_API_KEY', 'SHODAN_API_KEY'];
  const updates = {};
  for (const key of allowed) {
    if (req.body[key] !== undefined && req.body[key] !== '••••••••' && req.body[key] !== '') {
      updates[key] = req.body[key]; process.env[key] = req.body[key];
    }
  }
  await dbSaveSettings(updates).catch(() => {});
  res.json({ ok: true });
});

// ─── ADMIN API ────────────────────────────────────────────────────────────────
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const users = await dbGetAllUsers();
    const history = await dbGetHistory(null, true);
    res.json({ userCount: users.length, scanCount: history.length });
  } catch { res.json({ userCount: 0, scanCount: 0 }); }
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try { res.json(await dbGetAllUsers()); } catch { res.json([]); }
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  if (id === req.user.userId) return res.status(400).json({ error: 'Cannot delete yourself' });
  try { await dbDeleteUser(id); res.json({ ok: true }); }
  catch (e) { res.status(404).json({ error: e.message }); }
});

app.get('/api/admin/scans', requireAdmin, async (req, res) => {
  try { res.json(await dbGetHistory(null, true)); } catch { res.json([]); }
});

// ─── SHARE ────────────────────────────────────────────────────────────────────
app.post('/api/history/:id/share', requireAuth, async (req, res) => {
  try {
    const token = await dbGenerateShareToken(req.params.id, req.user.userId, req.user.isAdmin);
    const url = `${req.protocol}://${req.get('host')}/report/${token}`;
    res.json({ token, url });
  } catch (e) { res.status(404).json({ error: e.message }); }
});

// ─── PUBLIC REPORT PAGE ───────────────────────────────────────────────────────
app.get('/report/:token', async (req, res) => {
  try {
    const scan = await dbGetHistoryByToken(req.params.token);
    const findings = scan.findings || [];
    const high = findings.filter(f => f.severity === 'high').length;
    const medium = findings.filter(f => f.severity === 'medium').length;
    const low = findings.filter(f => f.severity === 'low').length;
    const info = findings.filter(f => f.severity === 'info').length;
    const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    const sevColor = s => ({high:'#ff2a2a',medium:'#f59e0b',low:'#00c8ff',info:'#8888a0'}[s]||'#8888a0');
    const findingsHtml = findings.map(f => `
      <div style="padding:10px 12px;margin-bottom:6px;background:#0a0a0e;border:1px solid #1a1a24;border-left:3px solid ${sevColor(f.severity)};">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px;">
          <span style="font-size:9px;font-weight:700;letter-spacing:1px;color:${sevColor(f.severity)};text-transform:uppercase;">${esc(f.severity)}</span>
          <span style="font-size:9px;color:#444458;">${esc(f.module)}</span>
        </div>
        <div style="font-size:11px;font-weight:600;color:#e0e0e8;margin-bottom:2px;">${esc(f.title)}</div>
        <div style="font-size:10px;color:#8888a0;">${esc(f.detail)}</div>
      </div>`).join('');
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>THREATOPS Report — ${esc(scan.target)}</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Share+Tech+Mono&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#050507;color:#e0e0e8;font-family:'JetBrains Mono',monospace;padding:24px;max-width:860px;margin:0 auto;font-size:12px;}
.logo{font-family:'Share Tech Mono',monospace;font-size:18px;color:#ff2a2a;letter-spacing:3px;margin-bottom:4px;}
.hdr{border-bottom:1px solid #1a1a24;padding-bottom:16px;margin-bottom:20px;}
.target{font-size:20px;font-weight:700;color:#e0e0e8;margin:12px 0 4px;}
.meta{font-size:10px;color:#444458;}
.counts{display:flex;gap:8px;margin:14px 0;}
.cnt{padding:4px 10px;font-size:10px;font-weight:700;border:1px solid;}
.cnt-h{color:#ff2a2a;border-color:rgba(255,42,42,.3);background:rgba(255,42,42,.08);}
.cnt-m{color:#f59e0b;border-color:rgba(245,158,11,.3);background:rgba(245,158,11,.08);}
.cnt-l{color:#00c8ff;border-color:rgba(0,200,255,.3);background:rgba(0,200,255,.08);}
.cnt-i{color:#8888a0;border-color:#1a1a24;background:rgba(255,255,255,.03);}
.sl{font-size:9.5px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:#444458;border-bottom:1px solid #1a1a24;padding-bottom:5px;margin:18px 0 10px;}
.footer{margin-top:32px;padding-top:16px;border-top:1px solid #1a1a24;font-size:9.5px;color:#444458;text-align:center;}
</style>
</head>
<body>
<div class="hdr">
  <div class="logo">⚔ THREATOPS</div>
  <div class="target">${esc(scan.target)}</div>
  <div class="meta">Scan completed ${new Date(scan.ts).toUTCString()}${scan.email ? ' · ' + esc(scan.email) : ''}</div>
  <div class="counts">
    ${high ? `<span class="cnt cnt-h">${high} HIGH</span>` : ''}
    ${medium ? `<span class="cnt cnt-m">${medium} MED</span>` : ''}
    ${low ? `<span class="cnt cnt-l">${low} LOW</span>` : ''}
    ${info ? `<span class="cnt cnt-i">${info} INFO</span>` : ''}
    ${!findings.length ? '<span style="color:#444458;font-size:10px;">No findings</span>' : ''}
  </div>
</div>
${findings.length ? `<div class="sl">Intelligence Findings</div>${findingsHtml}` : '<div style="color:#444458;font-size:11px;">No findings for this scan.</div>'}
<div class="footer">Generated by THREATOPS Threat Intelligence Platform</div>
</body></html>`);
  } catch { res.status(404).send('Report not found or link expired.'); }
});

// ─── ADMIN PAGE ───────────────────────────────────────────────────────────────
app.get('/admin', requireAdmin, (req, res) => {
  const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>THREATOPS // ADMIN</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Share+Tech+Mono&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#050507;color:#e0e0e8;font-family:'JetBrains Mono',monospace;font-size:12px;}
.topbar{background:#0a0a0e;border-bottom:2px solid #ff2a2a;padding:0 20px;height:48px;display:flex;align-items:center;gap:12px;}
.logo{font-family:'Share Tech Mono',monospace;font-size:17px;color:#ff2a2a;letter-spacing:3px;}
.badge{background:rgba(255,42,42,.15);color:#ff2a2a;font-size:9px;font-weight:700;letter-spacing:1px;padding:2px 7px;border:1px solid rgba(255,42,42,.3);}
.ml{margin-left:auto;display:flex;gap:8px;}
.btn{height:28px;padding:0 12px;background:#0f0f14;border:1px solid #1a1a24;color:#8888a0;font-family:'JetBrains Mono',monospace;font-size:10px;cursor:pointer;text-decoration:none;display:flex;align-items:center;transition:all .15s;}
.btn:hover{border-color:#00c8ff;color:#00c8ff;}
.btn-r{background:rgba(255,42,42,.1);border-color:rgba(255,42,42,.3);color:#ff2a2a;}
.btn-r:hover{background:rgba(255,42,42,.2);}
.wrap{padding:20px;max-width:1100px;margin:0 auto;}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin-bottom:20px;}
.stat{background:#0a0a0e;border:1px solid #1a1a24;padding:14px 16px;}
.stat-n{font-size:24px;font-weight:700;color:#e0e0e8;margin-bottom:3px;}
.stat-l{font-size:9.5px;color:#444458;letter-spacing:1px;text-transform:uppercase;}
.section{background:#0a0a0e;border:1px solid #1a1a24;margin-bottom:14px;}
.sec-hdr{padding:10px 14px;border-bottom:1px solid #1a1a24;font-size:10px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:#8888a0;}
table{width:100%;border-collapse:collapse;}
td,th{padding:8px 14px;text-align:left;border-bottom:1px solid #1a1a24;font-size:10.5px;}
th{font-size:9.5px;color:#444458;letter-spacing:1px;text-transform:uppercase;font-weight:600;}
tr:last-child td{border-bottom:none;}
tr:hover td{background:rgba(255,255,255,.02);}
.tag{padding:1px 6px;font-size:8.5px;font-weight:700;letter-spacing:.5px;}
.t-r{background:rgba(255,42,42,.1);color:#ff2a2a;border:1px solid rgba(255,42,42,.3);}
.t-c{background:rgba(0,200,255,.1);color:#00c8ff;border:1px solid rgba(0,200,255,.3);}
.del-btn{padding:2px 8px;background:rgba(255,42,42,.1);border:1px solid rgba(255,42,42,.2);color:#ff6b6b;font-size:9.5px;cursor:pointer;font-family:'JetBrains Mono',monospace;}
.del-btn:hover{background:rgba(255,42,42,.2);}
#toast{position:fixed;bottom:20px;right:20px;background:#0a0a0e;border:1px solid #1a1a24;border-left:3px solid #00e676;color:#00e676;padding:8px 14px;font-size:10.5px;display:none;}
</style>
</head>
<body>
<div class="topbar">
  <div class="logo">⚔ THREATOPS</div>
  <span class="badge">ADMIN</span>
  <div class="ml">
    <a href="/" class="btn">← Dashboard</a>
    <a href="/api/logout" class="btn btn-r">Logout</a>
  </div>
</div>
<div class="wrap">
  <div class="stats" id="stats">
    <div class="stat"><div class="stat-n" id="st-users">—</div><div class="stat-l">Total Users</div></div>
    <div class="stat"><div class="stat-n" id="st-scans">—</div><div class="stat-l">Total Scans</div></div>
  </div>
  <div class="section">
    <div class="sec-hdr">Users</div>
    <table><thead><tr><th>Username</th><th>Joined</th><th>Role</th><th></th></tr></thead>
    <tbody id="users-tbody"><tr><td colspan="4" style="color:#444458;">Loading...</td></tr></tbody></table>
  </div>
  <div class="section">
    <div class="sec-hdr">Recent Scans (all users)</div>
    <table><thead><tr><th>Target</th><th>User</th><th>Time</th><th>Findings</th></tr></thead>
    <tbody id="scans-tbody"><tr><td colspan="4" style="color:#444458;">Loading...</td></tr></tbody></table>
  </div>
</div>
<div id="toast"></div>
<script>
const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
function toast(msg) { const t = document.getElementById('toast'); t.textContent = msg; t.style.display='block'; setTimeout(()=>t.style.display='none',3000); }

async function load() {
  const [stats, users, scans] = await Promise.all([
    fetch('/api/admin/stats').then(r=>r.json()),
    fetch('/api/admin/users').then(r=>r.json()),
    fetch('/api/admin/scans').then(r=>r.json()),
  ]);
  document.getElementById('st-users').textContent = stats.userCount;
  document.getElementById('st-scans').textContent = stats.scanCount;

  const utb = document.getElementById('users-tbody');
  utb.innerHTML = users.length ? users.map(u => \`<tr>
    <td style="font-weight:600;color:#e0e0e8;">\${esc(u.username)}</td>
    <td style="color:#8888a0;">\${new Date(u.createdAt).toLocaleDateString()}</td>
    <td>\${u.isAdmin ? '<span class="tag t-r">ADMIN</span>' : '<span class="tag t-c">USER</span>'}</td>
    <td>\${u.isAdmin ? '' : \`<button class="del-btn" onclick="deleteUser('\${esc(u.id)}', '\${esc(u.username)}')">Delete</button>\`}</td>
  </tr>\`).join('') : '<tr><td colspan="4" style="color:#444458;">No users</td></tr>';

  const stb = document.getElementById('scans-tbody');
  stb.innerHTML = scans.length ? scans.slice(0,50).map(s => \`<tr>
    <td style="color:#e0e0e8;">\${esc(s.target)}</td>
    <td style="color:#8888a0;">\${esc(s.userId||'—')}</td>
    <td style="color:#8888a0;">\${new Date(s.ts).toLocaleString()}</td>
    <td>\${s.high ? \`<span class="tag t-r" style="margin-right:3px;">\${s.high}H</span>\` : ''}\${s.medium ? \`<span style="color:#f59e0b;font-size:9.5px;">\${s.medium}M</span>\` : ''}</td>
  </tr>\`).join('') : '<tr><td colspan="4" style="color:#444458;">No scans yet</td></tr>';
}

async function deleteUser(id, username) {
  if (!confirm('Delete user ' + username + ' and all their scans?')) return;
  const r = await fetch('/api/admin/users/' + id, { method: 'DELETE' });
  if (r.ok) { toast('User deleted'); load(); }
  else { const d = await r.json(); alert(d.error); }
}

load();
</script>
</body></html>`);
});

// ─── STATIC FILES ─────────────────────────────────────────────────────────────
app.use(requireAuth);
app.use(express.static(path.join(__dirname, 'public')));

// ─── DNS ENUMERATION ────────────────────────────────────────────────────────
async function dnsEnumerate(domain) {
  const types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA'];
  const results = {};
  await Promise.allSettled(types.map(async (type) => {
    try {
      const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`, { timeout: 8000 });
      const data = await res.json();
      results[type] = data.Answer || data.Authority || [];
    } catch { results[type] = []; }
  }));
  return results;
}

// ─── PORT SCANNER ───────────────────────────────────────────────────────────
const TOP_PORTS = [
  {port:21,service:'FTP'},{port:22,service:'SSH'},{port:23,service:'Telnet'},
  {port:25,service:'SMTP'},{port:53,service:'DNS'},{port:80,service:'HTTP'},
  {port:110,service:'POP3'},{port:135,service:'RPC'},{port:139,service:'NetBIOS'},
  {port:143,service:'IMAP'},{port:443,service:'HTTPS'},{port:445,service:'SMB'},
  {port:993,service:'IMAPS'},{port:995,service:'POP3S'},{port:1433,service:'MSSQL'},
  {port:1723,service:'PPTP'},{port:3306,service:'MySQL'},{port:3389,service:'RDP'},
  {port:5432,service:'PostgreSQL'},{port:5900,service:'VNC'},{port:6379,service:'Redis'},
  {port:8080,service:'HTTP-Alt'},{port:8443,service:'HTTPS-Alt'},{port:8888,service:'HTTP-Dev'},
  {port:27017,service:'MongoDB'},
];

function scanPort(host, port, timeout = 2000) {
  return new Promise((resolve) => {
    const sock = new net.Socket(); let done = false;
    const finish = (s) => { if (done) return; done = true; sock.destroy(); resolve(s); };
    sock.setTimeout(timeout);
    sock.on('connect', () => finish('open'));
    sock.on('timeout', () => finish('filtered'));
    sock.on('error', (e) => finish(e.code === 'ECONNREFUSED' ? 'closed' : 'filtered'));
    sock.on('close', () => { if (!done) finish('filtered'); });
    try { sock.connect(port, host); } catch { finish('error'); }
  });
}

async function portScan(host) {
  const results = await Promise.allSettled(TOP_PORTS.map(async ({ port, service }) => ({ port, service, status: await scanPort(host, port) })));
  return results.map(r => r.value || { port: 0, service: 'unknown', status: 'error' });
}

// ─── WHOIS ──────────────────────────────────────────────────────────────────
function doWhois(domain) {
  return new Promise((resolve) => {
    const t = setTimeout(() => resolve({ raw: '', error: 'timeout' }), 10000);
    try { whois.lookup(domain, (err, data) => { clearTimeout(t); resolve(err ? { raw: '', error: err.message } : { raw: data || '' }); }); }
    catch (e) { clearTimeout(t); resolve({ raw: '', error: e.message }); }
  });
}
function parseWhoisFields(raw) {
  const f = {};
  const P = { registrar: /registrar:\s*(.+)/i, created: /creat(?:ion|ed)[^\:]*:\s*(.+)/i, expires: /expir(?:y|ation|es)[^\:]*:\s*(.+)/i, updated: /updat(?:ed|e)[^\:]*:\s*(.+)/i, nameservers: /name\s*server:\s*(.+)/gi, registrant: /registrant(?:\s+organization)?:\s*(.+)/i, privacy: /privacy|redacted|protected|masked/i };
  for (const [k, rx] of Object.entries(P)) {
    if (k === 'nameservers') f.nameservers = [...new Set([...raw.matchAll(rx)].map(m => m[1].trim()))];
    else if (k === 'privacy') f.privacy = rx.test(raw);
    else { const m = raw.match(rx); if (m) f[k] = m[1].trim(); }
  }
  return f;
}

// ─── SSL/TLS ─────────────────────────────────────────────────────────────────
function checkSSL(host) {
  return new Promise((resolve) => {
    const sock = tls.connect(443, host, { servername: host, rejectUnauthorized: false }, () => {
      try {
        const cert = sock.getPeerCertificate(true), cipher = sock.getCipher(), proto = sock.getProtocol();
        sock.destroy();
        if (!cert?.subject) return resolve({ error: 'No certificate' });
        resolve({ subject: cert.subject, issuer: cert.issuer, validFrom: cert.valid_from, validTo: cert.valid_to, daysRemaining: Math.floor((new Date(cert.valid_to) - Date.now()) / 86400000), subjectAltNames: cert.subjectaltname || '', fingerprint: cert.fingerprint || '', cipher: cipher ? cipher.name : 'unknown', protocol: proto || 'unknown', selfSigned: !!(cert.issuer && cert.subject && cert.issuer.CN === cert.subject.CN) });
      } catch (e) { sock.destroy(); resolve({ error: e.message }); }
    });
    sock.setTimeout(8000, () => { sock.destroy(); resolve({ error: 'timeout' }); });
    sock.on('error', e => resolve({ error: e.message }));
  });
}

// ─── GEOIP ───────────────────────────────────────────────────────────────────
async function geoIPLookup(domain) {
  try {
    const addrs = await dns.resolve4(domain).catch(() => []);
    if (!addrs.length) return { error: 'Could not resolve to IP' };
    const ip = addrs[0];
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,asname,reverse,proxy,hosting,query`, { timeout: 8000 });
    const data = await res.json();
    return data.status === 'fail' ? { error: data.message, ip } : { ...data, resolvedIP: ip };
  } catch (e) { return { error: e.message }; }
}

// ─── WAF DETECTION ───────────────────────────────────────────────────────────
async function detectWAF(targetUrl) {
  try {
    const url = targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`;
    const res = await fetch(url, { timeout: 10000, headers: { 'User-Agent': 'Mozilla/5.0 (compatible; THREATOPS/1.0)' }, redirect: 'follow' });
    const headers = {}; res.headers.forEach((v, k) => { headers[k] = v; });
    const cookies = headers['set-cookie'] || '', server = headers['server'] || '';
    const det = []; const add = (n, e) => { if (!det.find(w => w.name === n)) det.push({ name: n, evidence: e }); };
    if (headers['cf-ray']) add('Cloudflare', 'cf-ray header');
    if (/cloudflare/i.test(server)) add('Cloudflare', 'Server header');
    if (/cf_clearance|__cfduid/i.test(cookies)) add('Cloudflare', 'Cookie');
    if (headers['x-sucuri-id'] || headers['x-sucuri-cache']) add('Sucuri', 'Sucuri header');
    if (/imperva|incapsula/i.test(server)) add('Imperva', 'Server header');
    if (/incap_ses|visid_incap/i.test(cookies)) add('Imperva', 'Cookie');
    if (/barracuda/i.test(server)) add('Barracuda', 'Server header');
    if (/f5|big-ip/i.test(server)) add('F5 BIG-IP', 'Server header');
    if (/BIGipServer/i.test(cookies)) add('F5 BIG-IP', 'Cookie');
    if (/mod_security|modsecurity/i.test(server)) add('ModSecurity', 'Server header');
    if (headers['x-akamai-transformed']) add('Akamai', 'Header');
    return { detected: det.length > 0, wafs: det, statusCode: res.status };
  } catch (e) { return { error: e.message, detected: false, wafs: [] }; }
}

// ─── SUBDOMAIN DISCOVERY ────────────────────────────────────────────────────
async function subdomainDiscovery(domain) {
  try {
    const res = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, { timeout: 15000 });
    if (!res.ok) throw new Error(`crt.sh ${res.status}`);
    const data = await res.json();
    const subs = new Set();
    for (const e of data) for (const n of (e.name_value || '').split('\n')) {
      const c = n.replace(/^\*\./, '').trim().toLowerCase();
      if (c.endsWith(domain) && c !== domain) subs.add(c);
    }
    const list = [...subs].slice(0, 50);
    const resolved = await Promise.allSettled(list.map(async sub => {
      try { return { subdomain: sub, ips: await dns.resolve4(sub), live: true }; }
      catch { return { subdomain: sub, ips: [], live: false }; }
    }));
    return resolved.map(r => r.value || r.reason);
  } catch (e) { return { error: e.message }; }
}

// ─── BREACH CHECK ───────────────────────────────────────────────────────────
async function breachCheck(email) {
  const key = process.env.HIBP_API_KEY;
  if (!key || key === 'your_hibp_key_here') return { error: 'No HIBP API key configured' };
  try {
    const res = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`, { headers: { 'hibp-api-key': key, 'User-Agent': 'THREATOPS-Dashboard' }, timeout: 10000 });
    if (res.status === 404) return { breaches: [], count: 0 };
    if (res.status === 401) return { error: 'Invalid HIBP API key' };
    if (!res.ok) return { error: `HIBP error: ${res.status}` };
    const b = await res.json(); return { breaches: b, count: b.length };
  } catch (e) { return { error: e.message }; }
}

// ─── TECH STACK ──────────────────────────────────────────────────────────────
async function techStackDetect(targetUrl) {
  try {
    const url = targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`;
    const res = await fetch(url, { timeout: 10000, headers: { 'User-Agent': 'Mozilla/5.0 (compatible; THREATOPS/1.0)' }, redirect: 'follow' });
    const headers = {}; res.headers.forEach((v, k) => { headers[k] = v; });
    const body = await res.text();
    const tech = [];
    if (headers['server']) tech.push({ name: headers['server'], category: 'Server', confidence: 'high' });
    if (headers['x-powered-by']) tech.push({ name: headers['x-powered-by'], category: 'Runtime', confidence: 'high' });
    const sc = headers['set-cookie'] || '';
    if (/PHPSESSID/i.test(sc)) tech.push({ name: 'PHP', category: 'Language', confidence: 'high' });
    if (/JSESSIONID/i.test(sc)) tech.push({ name: 'Java/Servlet', category: 'Runtime', confidence: 'high' });
    if (/laravel_session|XSRF-TOKEN/i.test(sc)) tech.push({ name: 'Laravel', category: 'Framework', confidence: 'high' });
    if (/django_csrftoken|csrftoken/i.test(sc)) tech.push({ name: 'Django', category: 'Framework', confidence: 'high' });
    const pats = [
      { rx: /wp-content|wp-includes/i, name: 'WordPress', category: 'CMS' },
      { rx: /Drupal\.settings|\/sites\/default\/files/i, name: 'Drupal', category: 'CMS' },
      { rx: /Joomla!/i, name: 'Joomla', category: 'CMS' },
      { rx: /shopify/i, name: 'Shopify', category: 'Ecommerce' },
      { rx: /magento/i, name: 'Magento', category: 'Ecommerce' },
      { rx: /_reactRootContainer|__REACT_DEVTOOLS|react\.production\.min/i, name: 'React', category: 'JS Framework' },
      { rx: /vue(?:\.min)?\.js|__vue__|Vue\.config/i, name: 'Vue.js', category: 'JS Framework' },
      { rx: /ng-version|angular(?:\.min)?\.js/i, name: 'Angular', category: 'JS Framework' },
      { rx: /jquery(?:\.min)?\.js/i, name: 'jQuery', category: 'JS Library' },
      { rx: /bootstrap(?:\.min)?\.(?:css|js)/i, name: 'Bootstrap', category: 'CSS Framework' },
      { rx: /__NEXT_DATA__|_next\/static/i, name: 'Next.js', category: 'SSR Framework' },
      { rx: /nuxt/i, name: 'Nuxt.js', category: 'SSR Framework' },
      { rx: /gatsby/i, name: 'Gatsby', category: 'Static Site' },
      { rx: /tailwindcss/i, name: 'Tailwind CSS', category: 'CSS Framework' },
      { rx: /svelte/i, name: 'Svelte', category: 'JS Framework' },
    ];
    for (const p of pats) if (p.rx.test(body) && !tech.find(t => t.name === p.name)) tech.push({ name: p.name, category: p.category, confidence: 'medium' });
    if (headers['cf-ray']) tech.push({ name: 'Cloudflare', category: 'CDN/WAF', confidence: 'high' });
    if (headers['x-amz-cf-id']) tech.push({ name: 'AWS CloudFront', category: 'CDN', confidence: 'high' });
    if (headers['x-vercel-id']) tech.push({ name: 'Vercel', category: 'Hosting', confidence: 'high' });
    if (headers['x-amzn-requestid'] || headers['x-amzn-trace-id']) tech.push({ name: 'AWS', category: 'Cloud', confidence: 'high' });
    return { tech, statusCode: res.status, finalUrl: res.url };
  } catch (e) { return { error: e.message, tech: [] }; }
}

// ─── HEADERS AUDIT ──────────────────────────────────────────────────────────
const SEC_HEADERS = [
  { key: 'content-security-policy', name: 'Content-Security-Policy', weight: 30, description: 'Prevents XSS and injection attacks' },
  { key: 'strict-transport-security', name: 'Strict-Transport-Security', weight: 25, description: 'Forces HTTPS, prevents SSL stripping' },
  { key: 'x-frame-options', name: 'X-Frame-Options', weight: 15, description: 'Prevents clickjacking' },
  { key: 'x-content-type-options', name: 'X-Content-Type-Options', weight: 10, description: 'Prevents MIME-type sniffing' },
  { key: 'referrer-policy', name: 'Referrer-Policy', weight: 10, description: 'Controls referrer leakage' },
  { key: 'permissions-policy', name: 'Permissions-Policy', weight: 10, description: 'Controls browser feature access' },
];
async function headersAudit(targetUrl) {
  try {
    const url = targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`;
    const res = await fetch(url, { timeout: 10000, headers: { 'User-Agent': 'Mozilla/5.0 (compatible; THREATOPS/1.0)' }, redirect: 'follow' });
    const headers = {}; res.headers.forEach((v, k) => { headers[k] = v; });
    let score = 0;
    const audit = SEC_HEADERS.map(h => {
      const val = headers[h.key]; const present = !!val;
      if (present) score += h.weight;
      let grade = 'MISSING';
      if (present) {
        if (h.key === 'strict-transport-security') { const ma = parseInt((val.match(/max-age=(\d+)/) || [])[1] || '0'); grade = ma >= 31536000 ? 'GOOD' : 'WEAK'; if (ma < 31536000) score -= h.weight * .5; }
        else if (h.key === 'x-content-type-options') grade = val.toLowerCase() === 'nosniff' ? 'GOOD' : 'WEAK';
        else if (h.key === 'x-frame-options') grade = /deny|sameorigin/i.test(val) ? 'GOOD' : 'WEAK';
        else grade = 'PRESENT';
      }
      return { ...h, value: val || null, present, grade };
    });
    score = Math.max(0, Math.min(100, Math.round(score)));
    const g = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 45 ? 'D' : score >= 25 ? 'E' : 'F';
    return { audit, score, letterGrade: g };
  } catch (e) { return { error: e.message, audit: [], score: 0, letterGrade: 'F' }; }
}

// ─── EMAIL SECURITY ──────────────────────────────────────────────────────────
async function emailSecurityCheck(domain) {
  const r = { spf: null, dmarc: null, dkim: [], mx: [] };
  r.mx = await dns.resolveMx(domain).then(x => x.sort((a, b) => a.priority - b.priority).map(x => ({ host: x.exchange, priority: x.priority }))).catch(() => []);
  try { const t = await dns.resolveTxt(domain); const s = t.flat().find(x => /^v=spf1/i.test(x)); r.spf = s ? { present: true, record: s, policy: /\-all$/i.test(s) ? 'hard-fail' : /\~all$/i.test(s) ? 'soft-fail' : 'neutral' } : { present: false }; } catch { r.spf = { present: false }; }
  try { const t = await dns.resolveTxt(`_dmarc.${domain}`); const s = t.flat().find(x => /^v=DMARC1/i.test(x)); r.dmarc = s ? { present: true, record: s, policy: (s.match(/p=(\w+)/i) || [])[1] || 'none', pct: parseInt((s.match(/pct=(\d+)/i) || [])[1] || '100') } : { present: false }; } catch { r.dmarc = { present: false }; }
  const sels = ['default', 'google', 'k1', 'mail', 'selector1', 'selector2', 'dkim', 'email', 's1', 's2'];
  const dk = await Promise.allSettled(sels.map(async sel => { try { const t = await dns.resolveTxt(`${sel}._domainkey.${domain}`); return t.flat().find(x => /^v=DKIM1/i.test(x)) ? { selector: sel, present: true } : null; } catch { return null; } }));
  r.dkim = dk.filter(x => x.status === 'fulfilled' && x.value).map(x => x.value);
  return r;
}

// ─── REVERSE DNS ────────────────────────────────────────────────────────────
async function reverseDNS(domain) {
  try {
    const v4 = await dns.resolve4(domain).catch(() => []);
    const v6 = await dns.resolve6(domain).catch(() => []);
    const all = [...v4.map(ip => ({ ip, version: 'IPv4' })), ...v6.map(ip => ({ ip, version: 'IPv6' }))];
    if (!all.length) return { error: 'No IPs resolved', records: [] };
    const records = await Promise.allSettled(all.slice(0, 10).map(async ({ ip, version }) => ({ ip, version, hostnames: await dns.reverse(ip).catch(() => []) })));
    return { records: records.map(r => r.value || r.reason) };
  } catch (e) { return { error: e.message, records: [] }; }
}

// ─── ABUSEIPDB ───────────────────────────────────────────────────────────────
async function checkAbuseIPDB(ip) {
  const key = process.env.ABUSEIPDB_API_KEY;
  if (!key || key === 'your_abuseipdb_key_here') return { error: 'No ABUSEIPDB_API_KEY configured' };
  try {
    const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, { headers: { 'Key': key, 'Accept': 'application/json' }, timeout: 10000 });
    if (!res.ok) return { error: `AbuseIPDB error: ${res.status}` };
    const j = await res.json(); return j.data || { error: 'No data' };
  } catch (e) { return { error: e.message }; }
}

// ─── SHODAN ──────────────────────────────────────────────────────────────────
async function shodanLookup(ip) {
  const key = process.env.SHODAN_API_KEY;
  if (!key || key === 'your_shodan_key_here') return { error: 'No SHODAN_API_KEY configured' };
  try {
    const res = await fetch(`https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${key}`, { timeout: 15000 });
    if (res.status === 404) return { error: 'No Shodan data for this IP' };
    if (!res.ok) return { error: `Shodan error: ${res.status}` };
    const d = await res.json();
    return { ip: d.ip_str, org: d.org, isp: d.isp, asn: d.asn, country: d.country_name, city: d.city, ports: d.ports || [], vulns: Object.keys(d.vulns || {}), hostnames: d.hostnames || [], tags: d.tags || [], lastUpdate: d.last_update, services: (d.data || []).slice(0, 10).map(s => ({ port: s.port, transport: s.transport, product: s.product || null, version: s.version || null, banner: (s.data || '').replace(/[\r\n]+/g, ' ').substring(0, 120) })) };
  } catch (e) { return { error: e.message }; }
}

// ─── HTTP PREVIEW ────────────────────────────────────────────────────────────
async function httpPreview(targetUrl) {
  try {
    const url = targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`;
    const res = await fetch(url, { timeout: 10000, headers: { 'User-Agent': 'Mozilla/5.0 (compatible; THREATOPS/1.0)' }, redirect: 'follow' });
    const headers = {}; res.headers.forEach((v, k) => { headers[k] = v; });
    const body = await res.text();
    const t = body.match(/<title[^>]*>([^<]+)<\/title>/i);
    const m = body.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)/i) || body.match(/<meta[^>]+content=["']([^"']+)["'][^>]+name=["']description["']/i);
    const g = body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)/i);
    return { statusCode: res.status, finalUrl: res.url, title: t ? t[1].trim().substring(0, 100) : null, description: m ? m[1].trim().substring(0, 200) : null, generator: g ? g[1].trim() : null, contentType: headers['content-type'] || null, bodySize: body.length, links: (body.match(/<a\s/gi) || []).length, scripts: (body.match(/<script/gi) || []).length, forms: (body.match(/<form/gi) || []).length, iframes: (body.match(/<iframe/gi) || []).length, preview: body.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '').replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().substring(0, 300) };
  } catch (e) { return { error: e.message }; }
}

// ─── FINDINGS ────────────────────────────────────────────────────────────────
function generateFindings(results) {
  const findings = [];
  const push = (s, t, d, m) => findings.push({ severity: s, title: t, detail: d, module: m, ts: new Date().toISOString() });

  if (results.dns && !results.dns.error) { const hasSPF = (results.dns.TXT || []).some(r => r.data && /v=spf1/i.test(r.data)); const hasDMARC = (results.dns.TXT || []).some(r => r.data && /v=DMARC1/i.test(r.data)); if (!hasSPF) push('medium', 'No SPF record', 'Domain vulnerable to email spoofing', 'DNS'); if (!hasDMARC) push('medium', 'No DMARC record', 'No enforcement against spoofed email', 'DNS'); }
  if (Array.isArray(results.ports)) { const open = results.ports.filter(p => p.status === 'open'); const risky = { 21: 'FTP', 23: 'Telnet', 1433: 'MSSQL', 3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB', 3389: 'RDP', 5900: 'VNC' }; for (const p of open) { if (risky[p.port]) push('high', `${risky[p.port]} (${p.port}) exposed`, `${risky[p.port]} publicly accessible`, 'Ports'); } if (open.some(p => p.port === 22)) push('info', 'SSH (22) open', 'Verify key-based auth and no root login', 'Ports'); if (open.some(p => [8080, 8443, 8888].includes(p.port))) push('low', 'Non-standard web port open', 'Dev/admin service may be exposed', 'Ports'); }
  if (results.ssl && !results.ssl.error) { const { daysRemaining: d, selfSigned, protocol } = results.ssl; if (d < 0) push('high', 'SSL certificate EXPIRED', `Expired ${Math.abs(d)} days ago`, 'SSL'); else if (d < 14) push('high', `SSL expires in ${d} days`, 'Urgent: renewal required', 'SSL'); else if (d < 30) push('medium', `SSL expires in ${d} days`, 'Schedule renewal', 'SSL'); if (selfSigned) push('high', 'Self-signed certificate', 'Not issued by a trusted CA', 'SSL'); if (protocol && /TLSv1\.0|TLSv1\.1|SSLv/i.test(protocol)) push('high', `Weak protocol: ${protocol}`, 'Upgrade to TLS 1.2 or 1.3', 'SSL'); }
  if (results.whois && !results.whois.error && results.whois.parsed?.expires) { const days = (new Date(results.whois.parsed.expires) - Date.now()) / 86400000; if (!isNaN(days) && days < 30) push('high', 'Domain expiring soon', `~${Math.round(days)} days remaining`, 'WHOIS'); else if (!isNaN(days) && days < 90) push('medium', 'Domain expires in <90 days', `Renew before ${results.whois.parsed.expires}`, 'WHOIS'); }
  if (Array.isArray(results.subdomains)) { const live = results.subdomains.filter(s => s.live); const sens = live.filter(s => /dev|staging|test|beta|admin|internal|vpn|jenkins|jira|gitlab|ci|uat/i.test(s.subdomain)); for (const d of sens.slice(0, 5)) push('high', `Sensitive subdomain: ${d.subdomain}`, 'Dev/admin host publicly resolvable', 'Subdomains'); if (live.length > 20) push('medium', `${live.length} live subdomains`, 'Large attack surface', 'Subdomains'); }
  if (results.breaches && !results.breaches.error && results.breaches.count > 0) push('high', `${results.breaches.count} data breach(es)`, `Found in: ${(results.breaches.breaches || []).slice(0, 3).map(b => b.Name).join(', ')}`, 'Breach');
  if (results.tech?.tech) { const cms = results.tech.tech.find(t => t.category === 'CMS'); if (cms) push('medium', `CMS: ${cms.name}`, 'Keep updated to avoid known CVEs', 'Tech'); const old = results.tech.tech.filter(t => /apache\/[12]\.|nginx\/1\.[0-9]\.|php\/[4567]\./i.test(t.name)); for (const o of old) push('high', `Potentially outdated: ${o.name}`, 'Old version may have known vulnerabilities', 'Tech'); }
  if (results.headers?.audit) { const miss = results.headers.audit.filter(h => !h.present); for (const m of miss) push(m.weight >= 25 ? 'high' : m.weight >= 15 ? 'medium' : 'low', `Missing: ${m.name}`, m.description, 'Headers'); if (results.headers.score < 30) push('high', `Security headers: ${results.headers.letterGrade} (${results.headers.score}/100)`, 'Very poor header posture', 'Headers'); }
  if (results.emailSecurity) { if (!results.emailSecurity.spf?.present) push('medium', 'SPF not configured', 'Domain vulnerable to spoofing', 'Email'); if (!results.emailSecurity.dmarc?.present) push('medium', 'DMARC not configured', 'No email auth enforcement', 'Email'); else if (results.emailSecurity.dmarc.policy === 'none') push('low', 'DMARC policy: none', 'Monitoring only — not enforcing', 'Email'); }
  if (results.waf) { if (results.waf.detected) push('info', `WAF: ${results.waf.wafs.map(w => w.name).join(', ')}`, 'Web application firewall detected', 'WAF'); else if (!results.waf.error) push('low', 'No WAF detected', 'Consider adding WAF protection', 'WAF'); }
  if (results.geoip && !results.geoip.error && results.geoip.proxy) push('medium', 'Proxy/VPN at target IP', 'Target may be behind a proxy', 'GeoIP');
  if (results.abuseipdb && !results.abuseipdb.error) { const s = results.abuseipdb.abuseConfidenceScore || 0; if (s > 75) push('high', `IP abuse score: ${s}%`, `${results.abuseipdb.totalReports || 0} reports — high risk`, 'AbuseIPDB'); else if (s > 25) push('medium', `IP abuse score: ${s}%`, 'Suspicious activity reported', 'AbuseIPDB'); }
  if (results.shodan && !results.shodan.error) { for (const v of (results.shodan.vulns || []).slice(0, 10)) push('high', `CVE: ${v}`, 'Vulnerability detected via Shodan', 'Shodan'); }
  if (results.httpPreview && !results.httpPreview.error && results.httpPreview.iframes > 0) push('low', `${results.httpPreview.iframes} iframe(s) detected`, 'Review for clickjacking vectors', 'Preview');

  const order = { high: 0, medium: 1, low: 2, info: 3 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);
  return findings;
}

// ─── HISTORY ROUTES ───────────────────────────────────────────────────────────
app.get('/api/history', requireAuth, async (req, res) => {
  try { res.json(await dbGetHistory(req.user.userId, req.user.isAdmin)); }
  catch { res.json([]); }
});

app.get('/api/history/:id', requireAuth, async (req, res) => {
  try { res.json(await dbGetHistoryItem(req.params.id.replace(/[^a-z0-9]/gi, ''), req.user.userId, req.user.isAdmin)); }
  catch { res.status(404).json({ error: 'Not found' }); }
});

app.delete('/api/history/:id', requireAuth, async (req, res) => {
  try { await dbDeleteHistory(req.params.id.replace(/[^a-z0-9]/gi, ''), req.user.userId, req.user.isAdmin); res.json({ ok: true }); }
  catch { res.status(404).json({ error: 'Not found' }); }
});

// ─── SCAN ENDPOINT ───────────────────────────────────────────────────────────
app.get('/api/scan', requireAuth, rateLimit, async (req, res) => {
  const { target, email } = req.query;
  if (!target) return res.status(400).json({ error: 'target required' });

  let domain = target.trim();
  try { if (domain.startsWith('http')) domain = new URL(domain).hostname; else if (domain.includes('/')) domain = domain.split('/')[0]; domain = domain.split(':')[0]; } catch {}

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.flushHeaders();

  let closed = false; req.on('close', () => { closed = true; });
  const send = (ev, data) => { if (closed) return; try { res.write(`event: ${ev}\ndata: ${JSON.stringify(data)}\n\n`); } catch {} };
  const hb = setInterval(() => { if (!closed) { try { res.write(': heartbeat\n\n'); } catch {} } }, 15000);

  // Queue handling
  if (activeScans >= MAX_CONCURRENT_SCANS) {
    send('status', { msg: `Queued — position ${scanQueue.length + 1}. Waiting for a scan slot...`, queued: true, position: scanQueue.length + 1 });
  }
  await acquireScanSlot();

  if (closed) { releaseScanSlot(); clearInterval(hb); return; }

  const scanId = Date.now().toString();
  send('status', { msg: `Scan initiated: ${domain}`, ts: new Date().toISOString() });

  let resolvedIP = null;
  try { [resolvedIP] = await dns.resolve4(domain); } catch {}

  const R = {};
  const T = (id, label, fn) => async () => {
    send('status', { msg: `${label}...`, module: id });
    const r = await fn().catch(e => ({ error: e.message }));
    R[id] = r; send(id, r);
    send('status', { msg: `${label.split(':')[0]}: complete`, module: id, done: true, error: !!r.error });
  };

  await Promise.allSettled([
    T('dns', 'DNS: querying records', () => dnsEnumerate(domain))(),
    T('ports', 'Ports: scanning top 25', () => portScan(domain))(),
    T('whois', 'WHOIS: looking up', () => doWhois(domain).then(r => ({ ...r, parsed: parseWhoisFields(r.raw || '') })))(),
    T('subdomains', 'Subdomains: querying crt.sh', () => subdomainDiscovery(domain))(),
    T('ssl', 'SSL: checking certificate', () => checkSSL(domain))(),
    T('geoip', 'GeoIP: locating target', () => geoIPLookup(domain))(),
    T('waf', 'WAF: detecting firewall', () => detectWAF(target))(),
    T('tech', 'Tech: fingerprinting stack', () => techStackDetect(target))(),
    T('headers', 'Headers: auditing security posture', () => headersAudit(target))(),
    T('emailSecurity', 'Email: checking SPF/DKIM/DMARC', () => emailSecurityCheck(domain))(),
    T('reverseDNS', 'Reverse DNS: resolving PTR records', () => reverseDNS(domain))(),
    T('httpPreview', 'Preview: fetching response', () => httpPreview(target))(),
    ...(email ? [T('breaches', 'Breach: checking HIBP', () => breachCheck(email))()] : [(async () => { send('breaches', { skipped: true }); })()]),
    ...(resolvedIP
      ? [T('abuseipdb', 'AbuseIPDB: checking IP reputation', () => checkAbuseIPDB(resolvedIP))(), T('shodan', 'Shodan: querying host data', () => shodanLookup(resolvedIP))()]
      : [(async () => { send('abuseipdb', { error: 'Could not resolve IP' }); send('status', { module: 'abuseipdb', done: true, error: true, msg: 'AbuseIPDB: no IP' }); })(),
        (async () => { send('shodan', { error: 'Could not resolve IP' }); send('status', { module: 'shodan', done: true, error: true, msg: 'Shodan: no IP' }); })()]),
  ]);

  releaseScanSlot();
  clearInterval(hb);
  const findings = generateFindings(R);
  await dbSaveHistory(scanId, req.user.userId, target, email || null, R, findings);
  send('findings', findings);
  send('done', { scanId, ts: new Date().toISOString(), counts: { high: findings.filter(f => f.severity === 'high').length, medium: findings.filter(f => f.severity === 'medium').length, low: findings.filter(f => f.severity === 'low').length, info: findings.filter(f => f.severity === 'info').length } });
  res.end();
});

// ─── START ────────────────────────────────────────────────────────────────────
initDB()
  .then(() => {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`THREATOPS running at http://localhost:${PORT} [${pool ? 'postgres' : 'file'} mode]`));
  })
  .catch(err => { console.error('DB init failed:', err); process.exit(1); });
