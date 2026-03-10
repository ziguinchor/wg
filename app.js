/**
 * wg-control (ESM) — JWT enforced on /api/* resources
 * CORS disabled
 *
 * Public:
 *   POST /auth/login
 *   GET  /health
 *
 * Protected:
 *   POST   /api/clients
 *   POST   /api/clients/by-public-key
 *   GET    /api/clients
 *   DELETE /api/clients/:id
 *   POST   /api/sync
 *
 * Install:
 *   npm i express mongoose nanoid jsonwebtoken bcryptjs
 *
 * Run:
 *   sudo node app.js
 */

import express from "express";
import mongoose from "mongoose";
import { nanoid } from "nanoid";
import { execFileSync } from "child_process";
import fs from "fs";
import path from "path";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import cors from "cors";

app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);

import Admin from "./models/Admin.js";

/** =========================
 * CONFIG
 * ========================= */
const CONFIG = {
  WG_IFACE: "wg0",
  SERVER_ENDPOINT: "51.222.139.224:51820",
  SERVER_PUBLIC_KEY: "afNgr4DPvJgPotG0v5sERQEBkIGjBB9fBfV2zkSnOGM=",
  DNS: "1.1.1.1, 8.8.8.8",
  VPN_IP_PREFIX: "10.0.0.",
  CLIENT_MTU: 1420,
  API_PORT: 9191,

  MONGODB_URI:
    process.env.MONGODB_URI ||
    "mongodb+srv://comaritc_db_user:lrBaDpBvhiAvlL88@wireguard-users.2g5q5fz.mongodb.net/wg_control?retryWrites=true&w=majority&appName=wireguard-users",

  JWT: {
    SECRET: process.env.JWT_SECRET || "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET",
    EXPIRES_IN: "12h",
    ISSUER: "wg-control"
  },

  ADMIN: {
    USERNAME: process.env.ADMIN_USERNAME || "admin",
    PASSWORD_BCRYPT:
      process.env.ADMIN_PASSWORD_BCRYPT ||
      "$2b$10$.jnMPA/bYTRADKpmcCqn1.tClAsF946OLdfwLPselAlmsdKhW6Ov6"
  },

  LOG_DIR: "./logs",
  LOG_FILE: "wg-control.log"
};

/** =========================
 * LOGGER (file + console)
 * ========================= */
const logDir = path.resolve(CONFIG.LOG_DIR);
fs.mkdirSync(logDir, { recursive: true });
const logPath = path.join(logDir, CONFIG.LOG_FILE);

function log(level, msg, meta) {
  const entry = { ts: new Date().toISOString(), level, msg, ...(meta ? { meta } : {}) };
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

/** =========================
 * MONGOOSE
 * ========================= */
const clientSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    name: { type: String, default: "client", trim: true },

    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      minlength: 3,
      maxlength: 64
    },

    passwordHash: {
      type: String,
      required: true
    },

    publicKey: { type: String, required: true, unique: true, index: true },
    privateKey: { type: String, default: null },
    ip: { type: String, required: true, unique: true, index: true },
    createdAt: { type: Date, required: true, default: Date.now },
    revoked: { type: Boolean, required: true, default: false }
  },
  {
    versionKey: false,
    collection: "clients"
  }
);

clientSchema.index({ username: 1 }, { unique: true });

const Client = mongoose.model("Client", clientSchema);

/** =========================
 * HELPERS
 * ========================= */
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

async function allocateIP() {
  const rows = await Client.find({ revoked: false }, { ip: 1, _id: 0 }).lean();
  const used = new Set(rows.map((r) => r.ip));

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

async function syncDbPeersToWireGuard() {
  const peers = await Client.find(
    { revoked: false },
    { publicKey: 1, ip: 1, _id: 0 }
  ).lean();

  for (const p of peers) {
    wgAddPeer(p.publicKey, p.ip);
  }

  return peers.length;
}

/** =========================
 * AUTH (JWT)
 * ========================= */
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
    req.user = jwt.verify(token, CONFIG.JWT.SECRET, {
      issuer: CONFIG.JWT.ISSUER
    });
    return next();
  } catch {
    return res.status(401).json({ error: "invalid_or_expired_token" });
  }
}

/** =========================
 * APP
 * ========================= */
const app = express();
app.use(express.json());


// Request log
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

/** ---------- PUBLIC ---------- */
app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    mongo: mongoose.connection.readyState === 1
    });
});

app.post("/auth/login", async (req, res, next) => {
  try {
    const username = (req.body?.username || "").toString().trim();
    const password = (req.body?.password || "").toString();

    const admin = await Admin.findOne({ username, isActive: true }).lean();

    if (!admin) {
      log("warn", "login_failed", { username, reason: "user_not_found" });
      return res.status(401).json({ error: "invalid_credentials" });
    }

    const ok = bcrypt.compareSync(password, admin.passwordHash);

    if (!ok) {
      log("warn", "login_failed", { username, reason: "bad_password" });
      return res.status(401).json({ error: "invalid_credentials" });
    }

    const token = signToken(admin.username);
    log("info", "login_success", { username: admin.username });

    return res.json({
      tokenType: "Bearer",
      token,
      expiresIn: CONFIG.JWT.EXPIRES_IN
    });
  } catch (err) {
    return next(err);
  }
});

/** ---------- PROTECTED ---------- */
const api = express.Router();
api.use(authRequired);

// POST /api/clients
api.post("/clients", async (req, res, next) => {
  try {
    const name = (req.body?.name || "client").toString().trim();
    const username = (req.body?.username || "").toString().trim();
    const password = (req.body?.password || "").toString();

    if (!username) {
      return res.status(400).json({ error: "username_required" });
    }

    if (username.length < 3) {
      return res.status(400).json({ error: "username_too_short" });
    }

    if (!password) {
      return res.status(400).json({ error: "password_required" });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: "password_too_short" });
    }

    const id = nanoid(10);
    const ip = await allocateIP();
    const { privateKey, publicKey } = generateKeypair();
    const passwordHash = bcrypt.hashSync(password, 10);

    const client = await Client.create({
      id,
      name,
      username,
      passwordHash,
      publicKey,
      privateKey,
      ip,
      createdAt: new Date(),
      revoked: false
    });

    try {
      wgAddPeer(publicKey, ip);
    } catch (e) {
      await Client.deleteOne({ _id: client._id });
      throw e;
    }

    return res.json({
      id,
      name,
      username,
      ip,
      publicKey,
      config: buildClientConfig(privateKey, ip)
    });
  } catch (err) {
    if (err?.code === 11000) {
      if (err?.keyPattern?.username) {
        return res.status(409).json({ error: "username_already_exists" });
      }
      return res.status(409).json({ error: "duplicate_client_or_ip" });
    }
    return next(err);
  }
});

// POST /api/clients/by-public-key
api.post("/clients/by-public-key", async (req, res, next) => {
  try {
    const name = (req.body?.name || "client").toString().trim();
    const username = (req.body?.username || "").toString().trim();
    const password = (req.body?.password || "").toString();
    const publicKey = (req.body?.publicKey || "").toString().trim();

    if (!username) {
      return res.status(400).json({ error: "username_required" });
    }

    if (username.length < 3) {
      return res.status(400).json({ error: "username_too_short" });
    }

    if (!password) {
      return res.status(400).json({ error: "password_required" });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: "password_too_short" });
    }

    if (!isLikelyWGKey(publicKey)) {
      return res.status(400).json({ error: "invalid_public_key" });
    }

    const id = nanoid(10);
    const ip = await allocateIP();
    const passwordHash = bcrypt.hashSync(password, 10);

    const client = await Client.create({
      id,
      name,
      username,
      passwordHash,
      publicKey,
      privateKey: null,
      ip,
      createdAt: new Date(),
      revoked: false
    });

    try {
      wgAddPeer(publicKey, ip);
    } catch (e) {
      await Client.deleteOne({ _id: client._id });
      throw e;
    }

    return res.json({
      id,
      name,
      username,
      ip,
      publicKey
    });
  } catch (err) {
    if (err?.code === 11000) {
      if (err?.keyPattern?.username) {
        return res.status(409).json({ error: "username_already_exists" });
      }
      return res.status(409).json({ error: "duplicate_client_or_ip" });
    }
    return next(err);
  }
});

// GET /api/clients
api.get("/clients", async (_req, res, next) => {
  try {
    const rows = await Client.find(
      {},
      {
        _id: 0,
        id: 1,
        name: 1,
        username: 1,
        publicKey: 1,
        ip: 1,
        createdAt: 1,
        revoked: 1
      }
    )
      .sort({ createdAt: -1 })
      .lean();

    const data = rows.map((r) => ({
      id: r.id,
      name: r.name,
      username: r.username,
      publicKey: r.publicKey,
      ip: r.ip,
      createdAt:
        r.createdAt instanceof Date ? r.createdAt.toISOString() : r.createdAt,
      revoked: r.revoked
    }));

    return res.json(data);
  } catch (err) {
    return next(err);
  }
});

// DELETE /api/clients/:id
api.delete("/clients/:id", async (req, res, next) => {
  try {
    const id = req.params.id;
    const row = await Client.findOne({ id }).lean();

    if (!row) {
      return res.status(404).json({ error: "not_found" });
    }

    if (row.revoked) {
      return res.json({ ok: true, alreadyRevoked: true });
    }

    wgRemovePeer(row.publicKey);
    await Client.updateOne({ id }, { $set: { revoked: true } });

    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
});

// POST /api/sync
api.post("/sync", async (_req, res, next) => {
  try {
    const count = await syncDbPeersToWireGuard();
    return res.json({ ok: true, appliedPeers: count });
  } catch (err) {
    return next(err);
  }
});

app.use("/api", api);

/** ---------- 404 + ERROR ---------- */
app.use((_req, res) => res.status(404).json({ error: "not_found" }));

app.use((err, req, res, _next) => {
  log("error", "expressError", {
    message: err?.message || "unknown",
    stack: err?.stack,
    path: req?.originalUrl,
    method: req?.method
  });
  res.status(500).json({ error: "internal_error" });
});

/** ---------- BOOT ---------- */
async function boot() {
  try {
    await mongoose.connect(CONFIG.MONGODB_URI);
    log("info", "mongodb_connected", { db: mongoose.connection.name });

    try {
      const applied = await syncDbPeersToWireGuard();
      log("info", "startupSyncComplete", { appliedPeers: applied });
    } catch (e) {
      log("error", "startupSyncFailed", {
        message: e?.message,
        stack: e?.stack
      });
    }

    app.listen(CONFIG.API_PORT, () => {
      log("info", "server_started", {
        port: CONFIG.API_PORT,
        public: ["GET /health", "POST /auth/login"],
        protected: [
          "POST /api/clients",
          "POST /api/clients/by-public-key",
          "GET /api/clients",
          "DELETE /api/clients/:id",
          "POST /api/sync"
        ],
        cors: "disabled"
      });
    });
  } catch (e) {
    log("error", "mongodb_connection_failed", {
      message: e?.message,
      stack: e?.stack
    });
    process.exit(1);
  }
}

boot();