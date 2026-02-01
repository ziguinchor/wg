/**
 * wg-control (ESM)
 * Auth: JWT + bcrypt
 *
 * Install:
 *   npm i express better-sqlite3 nanoid jsonwebtoken bcryptjs
 *
 * Run (needs root for `wg set`):
 *   sudo node app.js
 */

import express from "express";
import Database from "better-sqlite3";
import { nanoid } from "nanoid";
import { execFileSync } from "child_process";
import fs from "fs";
import path from "path";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

/**
 * =========================
 * CONFIG (EDIT THESE ONLY)
 * =========================
 */
const CONFIG = {
  WG_IFACE: "wg0",
  SERVER_ENDPOINT: "51.222.139.224:51820", // or "[IPv6]:51820"
  SERVER_PUBLIC_KEY: "PUT_SERVER_PUBLIC_KEY_HERE",
  DNS: "1.1.1.1, 8.8.8.8",
  VPN_IP_PREFIX: "10.0.0.", // allocates 10.0.0.2 .. 10.0.0.254
  CLIENT_MTU: 1420,
  API_PORT: 9191,

  // Logging
  LOG_DIR: "./logs",
  LOG_FILE: "wg-control.log",

  // JWT settings
  JWT: {
    // IMPORTANT: change this to a long random string
    SECRET: "CHANGE_ME_TO_A_LONG_RANDOM_SECRET_64+_CHARS",
    EXPIRES_IN: "12h",
    ISSUER: "wg-control"
  },

  // Admin account (bcrypt hash). Generate with /setup/hash below, then paste here.
  ADMIN: {
    USERNAME: "admin",
    // Default is hash for password: "change-this-strong-password"
    // You should generate your own and replace this.
    PASSWORD_BCRYPT:
      "$2b$10$.jnMPA/bYTRADKpmcCqn1.tClAsF946OLdfwLPselAlmsdKhW6Ov6"
  }
};

/**
 * =========================
 * LOGGER (file + console)
 * =========================
 */
const logDir = path.resolve(CONFIG.LOG_DIR);
fs.mkdirSync(logDir, { recursive: true });
const logPath = path.join(logDir, CONFIG.LOG_FILE);

function nowIso() {
  return new Date().toISOString();
}

function logLine(level, message, meta) {
  const entry = { ts: nowIso(), level, msg: message, ...(meta ? { meta } : {}) };
  const line = JSON.stringify(entry) + "\n";

  try {
    fs.appendFileSync(logPath, line, "utf8");
  } catch (e) {
    console.error("LOG_WRITE_FAILED", e?.message || e);
  }

  if (level === "error") console.error(entry);
  else if (level === "warn") console.warn(entry);
  else console.log(entry);
}

const log = {
  info: (m, meta) => logLine("info", m, meta),
  warn: (m, meta) => logLine("warn", m, meta),
  error: (m, meta) => logLine("error", m, meta)
};

// Global exception handlers
process.on("uncaughtException", (err) => {
  log.error("uncaughtException", { message: err?.message, stack: err?.stack });
  process.exit(1);
});
process.on("unhandledRejection", (reason) => {
  log.error("unhandledRejection", {
    reason: typeof reason === "string" ? reason : (reason?.message || "unknown"),
    stack: reason?.stack
  });
  process.exit(1);
});

/**
 * =========================
 * DB
 * =========================
 */
const db = new Database("wg.db");
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS clients (
  id TEXT PRIMARY KEY,
  name TEXT,
  public_key TEXT UNIQUE NOT NULL,
  private_key TEXT,        -- only present for /clients (server-generated)
  ip TEXT UNIQUE NOT NULL,
  created_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);
`);

/**
 * =========================
 * HELPERS
 * =========================
 */
function sh(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { encoding: "utf8", ...opts }).trim();
}

function isLikelyWGKey(k) {
  // WireGuard public keys are base64, 44 chars, ends with '='
  return typeof k === "string" && /^[A-Za-z0-9+/]{42}=$/.test(k.trim());
}

function generateKeypair() {
  const privateKey = sh("wg", ["genkey"]);
  const publicKey = sh("wg", ["pubkey"], { input: privateKey });
  return { privateKey, publicKey };
}

function allocateIP() {
  const used = new Set(
    db.prepare("SELECT ip FROM clients WHERE revoked=0").all().map((r) => r.ip)
  );

  for (let i = 2; i <= 254; i++) {
    const ip = `${CONFIG.VPN_IP_PREFIX}${i}`;
    if (!used.has(ip)) return ip;
  }
  throw new Error("No available IPs in pool");
}

function wgAddPeer(publicKey, ip) {
  sh("wg", ["set", CONFIG.WG_IFACE, "peer", publicKey, "allowed-ips", `${ip}/32`]);
  log.info("wgAddPeer", { publicKey, ip, iface: CONFIG.WG_IFACE });
}

function wgRemovePeer(publicKey) {
  sh("wg", ["set", CONFIG.WG_IFACE, "peer", publicKey, "remove"]);
  log.info("wgRemovePeer", { publicKey, iface: CONFIG.WG_IFACE });
}

function buildClientConfig({ clientPrivateKey, clientIP }) {
  // IMPORTANT: never log clientPrivateKey
  return `[Interface]
PrivateKey = ${clientPrivateKey}
Address = ${clientIP}/24
DNS = ${CONFIG.DNS}
MTU = ${CONFIG.CLIENT_MTU}

[Peer]
PublicKey = ${CONFIG.SERVER_PUBLIC_KEY}
Endpoint = ${CONFIG.SERVER_ENDPOINT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`;
}

function wrap(fn) {
  return (req, res, next) => {
    try {
      fn(req, res, next);
    } catch (e) {
      next(e);
    }
  };
}

/**
 * =========================
 * JWT AUTH
 * =========================
 */
function signToken({ username }) {
  return jwt.sign(
    { sub: username, role: "admin" },
    CONFIG.JWT.SECRET,
    { expiresIn: CONFIG.JWT.EXPIRES_IN, issuer: CONFIG.JWT.ISSUER }
  );
}

function authRequired(req, res, next) {
  const h = req.headers.authorization || "";
  if (!h.startsWith("Bearer ")) return res.status(401).json({ error: "missing_bearer_token" });

  const token = h.slice(7).trim();
  try {
    const payload = jwt.verify(token, CONFIG.JWT.SECRET, { issuer: CONFIG.JWT.ISSUER });
    req.user = payload; // { sub, role, iat, exp, iss }
    return next();
  } catch (e) {
    return res.status(401).json({ error: "invalid_or_expired_token" });
  }
}

/**
 * =========================
 * STARTUP SYNC
 * =========================
 */
function syncDbPeersToWireGuard() {
  const active = db.prepare(`
    SELECT public_key as publicKey, ip
    FROM clients
    WHERE revoked=0
  `).all();

  let applied = 0;
  for (const c of active) {
    wgAddPeer(c.publicKey, c.ip); // idempotent
    applied++;
  }
  return applied;
}

/**
 * =========================
 * API
 * =========================
 */
const app = express();
app.use(express.json());

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  const ip =
    req.headers["x-forwarded-for"]?.toString().split(",")[0]?.trim() ||
    req.socket.remoteAddress;

  res.on("finish", () => {
    log.info("http", {
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      ms: Date.now() - start,
      ip
    });
  });

  next();
});

/**
 * Helper endpoint: generate bcrypt hash for a password
 * (Remove this route after you set CONFIG.ADMIN.PASSWORD_BCRYPT)
 *
 * POST /setup/hash
 * Body: { "password": "mynewpassword" }
 */
app.post("/setup/hash", wrap((req, res) => {
  const password = (req.body?.password || "").toString();
  if (!password || password.length < 10) {
    return res.status(400).json({ error: "password must be at least 10 chars" });
  }
  const hash = bcrypt.hashSync(password, 10);
  res.json({ bcrypt: hash });
}));

/**
 * Login: username + password -> JWT
 *
 * POST /auth 
 * Body: { "username": "...", "password": "..." }
 * Response: { "token": "...", "expiresIn": "12h", "tokenType": "Bearer" }
 */
app.post("/auth/login", wrap((req, res) => {
  const username = (req.body?.username || "").toString();
  const password = (req.body?.password || "").toString();

  // avoid leaking whether username exists
  const userOk = username === CONFIG.ADMIN.USERNAME;
  const passOk = userOk && bcrypt.compareSync(password, CONFIG.ADMIN.PASSWORD_BCRYPT);

  if (!passOk) {
    log.warn("login_failed", { username });
    return res.status(401).json({ error: "invalid_credentials" });
  }

  const token = signToken({ username });
  log.info("login_success", { username });

  res.json({ tokenType: "Bearer", token, expiresIn: CONFIG.JWT.EXPIRES_IN });
}));

/**
 * Public health (no auth)
 */
app.get("/health", wrap((_req, res) => {
  res.json({ ok: true, iface: CONFIG.WG_IFACE, endpoint: CONFIG.SERVER_ENDPOINT });
}));

/**
 * Everything below requires JWT
 */
app.use(authRequired);

/**
 * POST /clients
 * Body: { "name": "phone" }
 */
app.post("/clients", wrap((req, res) => {
  const name = (req.body?.name || "client").toString();
  const id = nanoid(10);
  const ip = allocateIP();
  const { privateKey, publicKey } = generateKeypair();

  wgAddPeer(publicKey, ip);

  db.prepare(`
    INSERT INTO clients (id, name, public_key, private_key, ip, created_at, revoked)
    VALUES (?, ?, ?, ?, ?, ?, 0)
  `).run(id, name, publicKey, privateKey, ip, new Date().toISOString());

  log.info("clientCreated_serverKeys", { id, name, ip, publicKey, by: req.user?.sub });

  res.json({
    id,
    name,
    ip,
    publicKey,
    config: buildClientConfig({ clientPrivateKey: privateKey, clientIP: ip })
  });
}));

/**
 * POST /clients/by-public-key
 * Body: { "name": "laptop", "publicKey": "..." }
 */
app.post("/clients/by-public-key", wrap((req, res) => {
  const name = (req.body?.name || "client").toString();
  const publicKey = (req.body?.publicKey || "").toString().trim();

  if (!isLikelyWGKey(publicKey)) {
    log.warn("clientCreate_invalidPublicKey", { name, publicKey, by: req.user?.sub });
    return res.status(400).json({ error: "publicKey is invalid" });
  }

  const id = nanoid(10);
  const ip = allocateIP();

  wgAddPeer(publicKey, ip);

  db.prepare(`
    INSERT INTO clients (id, name, public_key, private_key, ip, created_at, revoked)
    VALUES (?, ?, ?, NULL, ?, ?, 0)
  `).run(id, name, publicKey, ip, new Date().toISOString());

  log.info("clientCreated_publicKeyOnly", { id, name, ip, publicKey, by: req.user?.sub });

  res.json({ id, name, ip, publicKey });
}));

/**
 * GET /clients
 */
app.get("/clients", wrap((_req, res) => {
  const rows = db.prepare(`
    SELECT id, name, public_key as publicKey, ip, created_at as createdAt, revoked
    FROM clients
    ORDER BY created_at DESC
  `).all();
  res.json(rows);
}));

/**
 * DELETE /clients/:id
 */
app.delete("/clients/:id", wrap((req, res) => {
  const id = req.params.id;
  const row = db.prepare(`
    SELECT public_key as publicKey, revoked
    FROM clients
    WHERE id=?
  `).get(id);

  if (!row) {
    log.warn("clientRevoke_notFound", { id, by: req.user?.sub });
    return res.status(404).json({ error: "not found" });
  }

  if (row.revoked) {
    log.info("clientRevoke_alreadyRevoked", { id, publicKey: row.publicKey, by: req.user?.sub });
    return res.json({ ok: true, alreadyRevoked: true });
  }

  wgRemovePeer(row.publicKey);
  db.prepare(`UPDATE clients SET revoked=1 WHERE id=?`).run(id);

  log.info("clientRevoked", { id, publicKey: row.publicKey, by: req.user?.sub });
  res.json({ ok: true });
}));

/**
 * POST /sync
 */
app.post("/sync", wrap((req, res) => {
  const count = syncDbPeersToWireGuard();
  log.info("syncTriggered", { appliedPeers: count, by: req.user?.sub });
  res.json({ ok: true, appliedPeers: count });
}));

/**
 * Express error handler (must be last)
 */
app.use((err, req, res, _next) => {
  log.error("expressError", {
    message: err?.message || "unknown",
    stack: err?.stack,
    path: req?.originalUrl,
    method: req?.method
  });
  res.status(500).json({ error: "internal_error" });
});

/**
 * =========================
 * BOOT
 * =========================
 */
try {
  const count = syncDbPeersToWireGuard();
  log.info("startupSyncComplete", { appliedPeers: count, iface: CONFIG.WG_IFACE });
} catch (e) {
  log.error("startupSyncFailed", { message: e?.message, stack: e?.stack });
}

app.listen(CONFIG.API_PORT, () => {
  log.info("serverStarted", { port: CONFIG.API_PORT });
  log.info("endpoints", {
    endpoints: [
      "POST /setup/hash (TEMP)",
      "POST /auth/login",
      "GET /health",
      "POST /clients (JWT)",
      "POST /clients/by-public-key (JWT)",
      "GET /clients (JWT)",
      "DELETE /clients/:id (JWT)",
      "POST /sync (JWT)"
    ]
  });
});
