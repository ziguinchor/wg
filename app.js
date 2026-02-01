/**
 * wg-control (ESM) — JWT-protected resources (bulletproof middleware order)
 *
 * Public:
 *   POST /auth/login
 *   GET  /health
 *
 * Protected (MUST include Authorization: Bearer <token>):
 *   POST   /clients
 *   POST   /clients/by-public-key
 *   GET    /clients
 *   DELETE /clients/:id
 *   POST   /sync
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
  SERVER_ENDPOINT: "51.222.139.224:51820",
  SERVER_PUBLIC_KEY: "PUT_SERVER_PUBLIC_KEY_HERE",
  DNS: "1.1.1.1, 8.8.8.8",
  VPN_IP_PREFIX: "10.0.0.",
  CLIENT_MTU: 1420,
  API_PORT: 9191,

  JWT: {
    SECRET: "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET",
    EXPIRES_IN: "12h",
    ISSUER: "wg-control"
  },

  ADMIN: {
    USERNAME: "admin",
    PASSWORD_BCRYPT:
      "$2b$10$.jnMPA/bYTRADKpmcCqn1.tClAsF946OLdfwLPselAlmsdKhW6Ov6"
  },

  LOG_DIR: "./logs",
  LOG_FILE: "wg-control.log"
};

/**
 * =========================
 * LOGGER (file + console)
 * =========================
 */
const logDir = path.resolve(CONFIG.LOG_DIR);
fs.mkdirSync(logDir, { recursive: true });
const logPath = path.join(logDir, CONFIG.LOG_FILE);

function log(level, msg, meta) {
  const entry = {
    ts: new Date().toISOString(),
    level,
    msg,
    ...(meta ? { meta } : {})
  };
  try {
    fs.appendFileSync(logPath, JSON.stringify(entry) + "\n", "utf8");
  } catch (e) {
    console.error("LOG_WRITE_FAILED", e?.message || e);
  }
  if (level === "error") console.error(entry);
  else if (level === "warn") console.warn(entry);
  else console.log(entry);
}

process.on("uncaughtException", (e) => {
  log("error", "uncaughtException", { message: e?.message, stack: e?.stack });
  process.exit(1);
});
process.on("unhandledRejection", (e) => {
  log("error", "unhandledRejection", { message: e?.message, stack: e?.stack });
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
  private_key TEXT,
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
  throw new Error("IP pool exhausted");
}

function wgAddPeer(publicKey, ip) {
  sh("wg", ["set", CONFIG.WG_IFACE, "peer", publicKey, "allowed-ips", `${ip}/32`]);
  log("info", "wgAddPeer", { publicKey, ip, iface: CONFIG.WG_IFACE });
}

function wgRemovePeer(publicKey) {
  sh("wg", ["set", CONFIG.WG_IFACE, "peer", publicKey, "remove"]);
  log("info", "wgRemovePeer", { publicKey, iface: CONFIG.WG_IFACE });
}

function buildClientConfig(priv, ip) {
  return `[Interface]
PrivateKey = ${priv}
Address = ${ip}/24
DNS = ${CONFIG.DNS}
MTU = ${CONFIG.CLIENT_MTU}

[Peer]
PublicKey = ${CONFIG.SERVER_PUBLIC_KEY}
Endpoint = ${CONFIG.SERVER_ENDPOINT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`;
}

function syncDbPeersToWireGuard() {
  const peers = db
    .prepare("SELECT public_key, ip FROM clients WHERE revoked=0")
    .all();
  for (const p of peers) {
    wgAddPeer(p.public_key, p.ip); // idempotent
  }
  return peers.length;
}

/**
 * =========================
 * AUTH
 * =========================
 */
function signToken(username) {
  return jwt.sign(
    { sub: username, role: "admin" },
    CONFIG.JWT.SECRET,
    { expiresIn: CONFIG.JWT.EXPIRES_IN, issuer: CONFIG.JWT.ISSUER }
  );
}

function authRequired(req, res, next) {
  const h = req.headers.authorization || "";
  if (!h.startsWith("Bearer ")) {
    return res.status(401).json({ error: "missing_token" });
  }

  const token = h.slice(7).trim();
  try {
    req.user = jwt.verify(token, CONFIG.JWT.SECRET, { issuer: CONFIG.JWT.ISSUER });
    return next();
  } catch {
    return res.status(401).json({ error: "invalid_or_expired_token" });
  }
}

/**
 * =========================
 * APP
 * =========================
 */
const app = express();
app.use(express.json());

// Request log (safe)
app.use((req, res, next) => {
  const start = Date.now();
  const ip =
    req.headers["x-forwarded-for"]?.toString().split(",")[0]?.trim() ||
    req.socket.remoteAddress;

  res.on("finish", () => {
    log("info", "http", {
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
 * =========================
 * PUBLIC ROUTER
 * =========================
 */
const publicRouter = express.Router();

publicRouter.get("/health", (_req, res) => res.json({ ok: true }));

publicRouter.post("/auth/login", (req, res) => {
  const username = (req.body?.username || "").toString();
  const password = (req.body?.password || "").toString();

  const ok =
    username === CONFIG.ADMIN.USERNAME &&
    bcrypt.compareSync(password, CONFIG.ADMIN.PASSWORD_BCRYPT);

  if (!ok) {
    log("warn", "login_failed", { username });
    return res.status(401).json({ error: "invalid_credentials" });
  }

  const token = signToken(username);
  log("info", "login_success", { username });

  return res.json({
    tokenType: "Bearer",
    token,
    expiresIn: CONFIG.JWT.EXPIRES_IN
  });
});

app.use(publicRouter);

/**
 * =========================
 * PROTECTED ROUTER (resources)
 * =========================
 * Everything in this router is protected, always.
 */
const protectedRouter = express.Router();
protectedRouter.use(authRequired);

protectedRouter.post("/clients", (req, res) => {
  const name = (req.body?.name || "client").toString();
  const id = nanoid(10);
  const ip = allocateIP();
  const { privateKey, publicKey } = generateKeypair();

  wgAddPeer(publicKey, ip);

  db.prepare(`
    INSERT INTO clients (id, name, public_key, private_key, ip, created_at, revoked)
    VALUES (?, ?, ?, ?, ?, ?, 0)
  `).run(id, name, publicKey, privateKey, ip, new Date().toISOString());

  log("info", "clientCreated_serverKeys", { id, name, ip, publicKey, by: req.user?.sub });

  res.json({
    id,
    name,
    ip,
    publicKey,
    config: buildClientConfig(privateKey, ip)
  });
});

protectedRouter.post("/clients/by-public-key", (req, res) => {
  const name = (req.body?.name || "client").toString();
  const publicKey = (req.body?.publicKey || "").toString().trim();

  if (!isLikelyWGKey(publicKey)) {
    log("warn", "clientCreate_invalidPublicKey", { name, publicKey, by: req.user?.sub });
    return res.status(400).json({ error: "invalid_public_key" });
  }

  const id = nanoid(10);
  const ip = allocateIP();

  wgAddPeer(publicKey, ip);

  db.prepare(`
    INSERT INTO clients (id, name, public_key, private_key, ip, created_at, revoked)
    VALUES (?, ?, ?, NULL, ?, ?, 0)
  `).run(id, name, publicKey, ip, new Date().toISOString());

  log("info", "clientCreated_publicKeyOnly", { id, name, ip, publicKey, by: req.user?.sub });

  res.json({ id, name, ip, publicKey });
});

protectedRouter.get("/clients", (_req, res) => {
  const rows = db.prepare(`
    SELECT id, name, public_key AS publicKey, ip, created_at AS createdAt, revoked
    FROM clients
    ORDER BY created_at DESC
  `).all();
  res.json(rows);
});

protectedRouter.delete("/clients/:id", (req, res) => {
  const id = req.params.id;
  const row = db.prepare("SELECT public_key, revoked FROM clients WHERE id=?").get(id);

  if (!row) {
    log("warn", "clientRevoke_notFound", { id, by: req.user?.sub });
    return res.status(404).json({ error: "not_found" });
  }

  if (row.revoked) {
    log("info", "clientRevoke_alreadyRevoked", { id, by: req.user?.sub });
    return res.json({ ok: true, alreadyRevoked: true });
  }

  wgRemovePeer(row.public_key);
  db.prepare("UPDATE clients SET revoked=1 WHERE id=?").run(id);

  log("info", "clientRevoked", { id, publicKey: row.public_key, by: req.user?.sub });
  res.json({ ok: true });
});

protectedRouter.post("/sync", (req, res) => {
  const count = syncDbPeersToWireGuard();
  log("info", "syncTriggered", { appliedPeers: count, by: req.user?.sub });
  res.json({ ok: true, appliedPeers: count });
});

// mount protected routes
app.use(protectedRouter);

/**
 * =========================
 * 404 + ERROR HANDLER
 * =========================
 */
app.use((req, res) => {
  res.status(404).json({ error: "not_found" });
});

app.use((err, req, res, _next) => {
  log("error", "expressError", {
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
  const applied = syncDbPeersToWireGuard();
  log("info", "startupSyncComplete", { appliedPeers: applied, iface: CONFIG.WG_IFACE });
} catch (e) {
  log("error", "startupSyncFailed", { message: e?.message, stack: e?.stack });
}

app.listen(CONFIG.API_PORT, () => {
  log("info", "server_started", {
    port: CONFIG.API_PORT,
    public: ["GET /health", "POST /auth/login"],
    protected: [
      "POST /clients",
      "POST /clients/by-public-key",
      "GET /clients",
      "DELETE /clients/:id",
      "POST /sync"
    ]
  });
});
