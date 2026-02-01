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
 * LOGGER
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
  fs.appendFileSync(logPath, JSON.stringify(entry) + "\n");
  if (level === "error") console.error(entry);
  else console.log(entry);
}

process.on("uncaughtException", e => {
  log("error", "uncaughtException", { message: e.message, stack: e.stack });
  process.exit(1);
});

process.on("unhandledRejection", e => {
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
  return /^[A-Za-z0-9+/]{42}=$/.test(k);
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
  throw new Error("IP pool exhausted");
}

function wgAddPeer(publicKey, ip) {
  sh("wg", ["set", CONFIG.WG_IFACE, "peer", publicKey, "allowed-ips", `${ip}/32`]);
}

function wgRemovePeer(publicKey) {
  sh("wg", ["set", CONFIG.WG_IFACE, "peer", publicKey, "remove"]);
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
  try {
    req.user = jwt.verify(h.slice(7), CONFIG.JWT.SECRET, {
      issuer: CONFIG.JWT.ISSUER
    });
    next();
  } catch {
    res.status(401).json({ error: "invalid_token" });
  }
}

/**
 * =========================
 * APP
 * =========================
 */
const app = express();
app.use(express.json());

// request log
app.use((req, res, next) => {
  const start = Date.now();
  res.on("finish", () => {
    log("info", "http", {
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      ms: Date.now() - start
    });
  });
  next();
});

/**
 * LOGIN (PUBLIC)
 */
app.post("/auth/login", (req, res) => {
  const { username, password } = req.body || {};

  if (
    username !== CONFIG.ADMIN.USERNAME ||
    !bcrypt.compareSync(password || "", CONFIG.ADMIN.PASSWORD_BCRYPT)
  ) {
    log("warn", "login_failed", { username });
    return res.status(401).json({ error: "invalid_credentials" });
  }

  const token = signToken(username);
  log("info", "login_success", { username });

  res.json({
    tokenType: "Bearer",
    token,
    expiresIn: CONFIG.JWT.EXPIRES_IN
  });
});

/**
 * EVERYTHING BELOW IS PROTECTED
 */
app.use(authRequired);

/**
 * HEALTH
 */
app.get("/health", (_req, res) => {
  res.json({ ok: true, iface: CONFIG.WG_IFACE });
});

/**
 * CREATE CLIENT
 */
app.post("/clients", (_req, res) => {
  const name = _req.body?.name || "client";
  const id = nanoid(10);
  const ip = allocateIP();
  const { privateKey, publicKey } = generateKeypair();

  wgAddPeer(publicKey, ip);

  db.prepare(`
    INSERT INTO clients VALUES (?, ?, ?, ?, ?, ?, 0)
  `).run(id, name, publicKey, privateKey, ip, new Date().toISOString());

  res.json({
    id,
    name,
    ip,
    publicKey,
    config: buildClientConfig(privateKey, ip)
  });
});

/**
 * CREATE CLIENT (PUBLIC KEY ONLY)
 */
app.post("/clients/by-public-key", (req, res) => {
  const { name = "client", publicKey } = req.body || {};
  if (!isLikelyWGKey(publicKey)) {
    return res.status(400).json({ error: "invalid_public_key" });
  }

  const id = nanoid(10);
  const ip = allocateIP();

  wgAddPeer(publicKey, ip);

  db.prepare(`
    INSERT INTO clients VALUES (?, ?, ?, NULL, ?, ?, 0)
  `).run(id, name, publicKey, ip, new Date().toISOString());

  res.json({ id, name, ip, publicKey });
});

/**
 * LIST CLIENTS
 */
app.get("/clients", (_req, res) => {
  res.json(
    db.prepare(`
      SELECT id, name, public_key AS publicKey, ip, created_at AS createdAt, revoked
      FROM clients
    `).all()
  );
});

/**
 * REVOKE CLIENT
 */
app.delete("/clients/:id", (req, res) => {
  const row = db.prepare(
    "SELECT public_key, revoked FROM clients WHERE id=?"
  ).get(req.params.id);

  if (!row) return res.status(404).json({ error: "not_found" });
  if (row.revoked) return res.json({ ok: true });

  wgRemovePeer(row.public_key);
  db.prepare("UPDATE clients SET revoked=1 WHERE id=?").run(req.params.id);

  res.json({ ok: true });
});

/**
 * SYNC
 */
app.post("/sync", (_req, res) => {
  const peers = db.prepare(
    "SELECT public_key, ip FROM clients WHERE revoked=0"
  ).all();
  peers.forEach(p => wgAddPeer(p.public_key, p.ip));
  res.json({ ok: true, appliedPeers: peers.length });
});

/**
 * START
 */
app.listen(CONFIG.API_PORT, () => {
  log("info", "server_started", { port: CONFIG.API_PORT });
});
