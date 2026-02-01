import express from "express";
import Database from "better-sqlite3";
import { nanoid } from "nanoid";
import { execFileSync } from "child_process";
import fs from "fs";
import path from "path";

/**
 * =========================
 * CONFIG (EDIT THESE ONLY)
 * =========================
 */
const CONFIG = {
  WG_IFACE: "wg0",
  SERVER_ENDPOINT: "51.222.139.224:51820", // or "[IPv6]:51820"
  SERVER_PUBLIC_KEY: "afNgr4DPvJgPotG0v5sERQEBkIGjBB9fBfV2zkSnOGM=",
  DNS: "1.1.1.1, 8.8.8.8",
  VPN_IP_PREFIX: "10.0.0.", // allocates 10.0.0.2 .. 10.0.0.254
  CLIENT_MTU: 1420,
  API_PORT: 9191,

  // Logging
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

function nowIso() {
  return new Date().toISOString();
}

function logLine(level, message, meta) {
  const entry = {
    ts: nowIso(),
    level,
    msg: message,
    ...(meta ? { meta } : {})
  };
  const line = JSON.stringify(entry) + "\n";
  try {
    fs.appendFileSync(logPath, line, "utf8");
  } catch (e) {
    // If file logging fails, still try console
    console.error("LOG_WRITE_FAILED", e?.message || e);
  }

  // Console mirror
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
    db.prepare("SELECT ip FROM clients WHERE revoked=0").all().map(r => r.ip)
  );

  for (let i = 2; i <= 254; i++) {
    const ip = `${CONFIG.VPN_IP_PREFIX}${i}`;
    if (!used.has(ip)) return ip;
  }
  throw new Error("No available IPs in pool");
}

function wgAddPeer(publicKey, ip) {
  // Adds peer live, no restart
  sh("wg", ["set", CONFIG.WG_IFACE, "peer", publicKey, "allowed-ips", `${ip}/32`]);
  log.info("wgAddPeer", { publicKey, ip, iface: CONFIG.WG_IFACE });
}

function wgRemovePeer(publicKey) {
  sh("wg", ["set", CONFIG.WG_IFACE, "peer", publicKey, "remove"]);
  log.info("wgRemovePeer", { publicKey, iface: CONFIG.WG_IFACE });
}

function buildClientConfig({ clientPrivateKey, clientIP }) {
  // IMPORTANT: do not log clientPrivateKey anywhere
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

// Express wrapper for sync handlers
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
  const ip = req.headers["x-forwarded-for"]?.toString().split(",")[0]?.trim() || req.socket.remoteAddress;

  res.on("finish", () => {
    const ms = Date.now() - start;
    log.info("http", {
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      ms,
      ip
    });
  });

  next();
});

app.get("/health", wrap((_req, res) => {
  res.json({
    ok: true,
    iface: CONFIG.WG_IFACE,
    endpoint: CONFIG.SERVER_ENDPOINT
  });
}));

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

  log.info("clientCreated_serverKeys", { id, name, ip, publicKey });

  res.json({
    id,
    name,
    ip,
    publicKey,
    config: buildClientConfig({ clientPrivateKey: privateKey, clientIP: ip })
  });
}));

app.post("/clients/by-public-key", wrap((req, res) => {
  const name = (req.body?.name || "client").toString();
  const publicKey = (req.body?.publicKey || "").toString().trim();

  if (!isLikelyWGKey(publicKey)) {
    log.warn("clientCreate_invalidPublicKey", { name, publicKey });
    return res.status(400).json({ error: "publicKey is invalid" });
  }

  const id = nanoid(10);
  const ip = allocateIP();

  wgAddPeer(publicKey, ip);

  db.prepare(`
    INSERT INTO clients (id, name, public_key, private_key, ip, created_at, revoked)
    VALUES (?, ?, ?, NULL, ?, ?, 0)
  `).run(id, name, publicKey, ip, new Date().toISOString());

  log.info("clientCreated_publicKeyOnly", { id, name, ip, publicKey });

  res.json({ id, name, ip, publicKey });
}));

app.get("/clients", wrap((_req, res) => {
  const rows = db.prepare(`
    SELECT id, name, public_key as publicKey, ip, created_at as createdAt, revoked
    FROM clients
    ORDER BY created_at DESC
  `).all();
  res.json(rows);
}));

app.delete("/clients/:id", wrap((req, res) => {
  const id = req.params.id;
  const row = db.prepare(`
    SELECT public_key as publicKey, revoked
    FROM clients
    WHERE id=?
  `).get(id);

  if (!row) {
    log.warn("clientRevoke_notFound", { id });
    return res.status(404).json({ error: "not found" });
  }

  if (row.revoked) {
    log.info("clientRevoke_alreadyRevoked", { id, publicKey: row.publicKey });
    return res.json({ ok: true, alreadyRevoked: true });
  }

  wgRemovePeer(row.publicKey);
  db.prepare(`UPDATE clients SET revoked=1 WHERE id=?`).run(id);

  log.info("clientRevoked", { id, publicKey: row.publicKey });

  res.json({ ok: true });
}));

app.post("/sync", wrap((_req, res) => {
  const count = syncDbPeersToWireGuard();
  log.info("syncTriggered", { appliedPeers: count });
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
  // don’t exit; API can still start
}

app.listen(CONFIG.API_PORT, () => {
  log.info("serverStarted", { port: CONFIG.API_PORT });
  log.info("endpoints", {
    endpoints: [
      "GET /health",
      "POST /clients",
      "POST /clients/by-public-key",
      "GET /clients",
      "DELETE /clients/:id",
      "POST /sync"
    ]
  });
});
