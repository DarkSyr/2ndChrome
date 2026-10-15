'use strict';

const express = require("express");
const {
    spawn,
    execFileSync
} = require("child_process");
const fs = require("fs");
const path = require("path");
const http = require("http");
const net = require("net");
const os = require("os");
const crypto = require("crypto");
const session = require("express-session");
const bcrypt = require("bcryptjs");

const app = express();

const PORT =
    Number(process.env.PORT || 3000);

const DISPLAY = ":99";

const INITIAL_VNC_PORT =
    Number(process.env.VNC_PORT || 15900);

const INITIAL_WEBSOCKIFY_PORT =
    Number(process.env.WEBSOCKIFY_PORT || 6080);

const ROOT = __dirname;

const PUBLIC_DIR =
    path.join(ROOT, "public");

const TIMER_STATE_FILE =
    path.join(ROOT, ".server-time-limit.json");

const PRO_USERS_DIR =
    path.join(
        process.env.HOME || os.homedir(),
        "workspace",
        "SavedUsers"
    );

const DEFAULT_PROFILE_NAME =
    "pro-profile";

const ACCESS_FILE =
    path.join(ROOT, ".access-links.json");

const ADMIN_FILE =
    path.join(ROOT, ".admin.json");

const SECRET_KEY =
    process.env.SECRET_KEY || process.env.SERVER_SECRET || null;

let runtimeSecret = SECRET_KEY;
if (!runtimeSecret) {
    // generate a runtime secret if none provided (tokens won't survive restarts)
    runtimeSecret = crypto.randomBytes(32).toString("hex");
    console.warn("WARNING: No SECRET_KEY provided. Generated ephemeral secret; tokens will not survive server restart.");
}

// Helper: read/write access file
function readAccessFile() {
    try {
        if (!fs.existsSync(ACCESS_FILE)) return {};
        const raw = fs.readFileSync(ACCESS_FILE, "utf8");
        return JSON.parse(raw || "{}");
    } catch (err) {
        console.error("[ACCESS] Read failed:", err.message);
        return {};
    }
}
function writeAccessFile(obj) {
    try {
        fs.writeFileSync(ACCESS_FILE, JSON.stringify(obj, null, 2), "utf8");
    } catch (err) {
        console.error("[ACCESS] Write failed:", err.message);
    }
}

// Admin password bootstrap: if ADMIN_PASSWORD provided in env during first run, save hash.
if (process.env.ADMIN_PASSWORD && !fs.existsSync(ADMIN_FILE)) {
    const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10);
    fs.writeFileSync(ADMIN_FILE, JSON.stringify({ hash }, null, 2), "utf8");
    console.log("[ADMIN] Admin password initialized from env and saved to .admin.json");
}

// ============================================================
// your existing server code continues unchanged for display/timer/watchdog/child-process management...
// For brevity in this snippet I keep existing code intact — below I only add the auth/token endpoints and small supporting helpers.
// Insert the rest of the file you already have (Xvfb, vnc, websockify, chrome, watchdog, etc.).
// ...
// ============================================================

// ---------- SESSION / AUTH ----------
app.use(express.json());

// Simple in-memory session store using express-session
app.use(session({
    secret: runtimeSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        // set secure:true if serving over https
        secure: process.env.NODE_ENV === 'production'
    }
}));

app.use("/novnc", express.static(path.join(ROOT, "node_modules", "@novnc", "novnc")));
app.use(express.static(PUBLIC_DIR));

// ---------- TOKEN UTIL ----------
function base64url(input) {
    if (Buffer.isBuffer(input)) {
        return input.toString('base64url');
    } else {
        return Buffer.from(String(input)).toString('base64url');
    }
}

function generateToken(user, ttlMs = 60 * 60 * 1000) {
    const expires = Date.now() + Number(ttlMs || 0);
    const nonce = crypto.randomBytes(10).toString('hex');
    const payload = JSON.stringify({ user: user || null, expires, nonce });
    const payloadB64 = base64url(payload);
    const hmac = crypto.createHmac('sha256', runtimeSecret).update(payloadB64).digest('base64url');
    return `${payloadB64}.${hmac}`;
}

function verifyToken(token) {
    try {
        const parts = String(token).split('.');
        if (parts.length !== 2) return null;
        const [payloadB64, sig] = parts;
        const expected = crypto.createHmac('sha256', runtimeSecret).update(payloadB64).digest('base64url');
        if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
        const payloadJson = Buffer.from(payloadB64, 'base64url').toString('utf8');
        const payload = JSON.parse(payloadJson);
        if (!payload.expires || Date.now() > payload.expires) return null;
        return payload; // contains { user, expires, nonce }
    } catch (err) {
        return null;
    }
}

// ---------- ADMIN LOGIN ----------
app.post('/api/admin/login', (req, res) => {
    try {
        const body = req.body || {};
        const pw = String(body.password || '');
        if (!fs.existsSync(ADMIN_FILE)) {
            return res.status(500).json({ success: false, error: "Admin not configured on server." });
        }
        const raw = JSON.parse(fs.readFileSync(ADMIN_FILE, 'utf8'));
        const hash = raw.hash;
        if (!bcrypt.compareSync(pw, hash)) {
            return res.status(401).json({ success: false, error: "Invalid password" });
        }
        req.session.admin = true;
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/admin/logout', (req, res) => {
    req.session.destroy(() => {
        res.json({ success: true });
    });
});

// Middleware to require admin
function requireAdmin(req, res, next) {
    if (req.session && req.session.admin) return next();
    return res.status(403).json({ success: false, error: "Admin login required" });
}

// ---------- GENERATE LINK ----------
/*
 Request:
 {
   user: "Alice" | null,
   hours: number,      // optional TTL hours
   save: boolean       // whether to persist the link in .access-links.json (only if user given)
 }
 Response:
 { success: true, url: "https://hostname/access/<token>", token }
*/
app.post('/api/generate-link', requireAdmin, (req, res) => {
    try {
        const body = req.body || {};
        const user = body.user ? String(body.user).trim() : null;
        const hours = Number(body.hours || 1);
        if (!Number.isFinite(hours) || hours <= 0) {
            return res.status(400).json({ success: false, error: "hours must be positive number" });
        }
        const ttlMs = hours * 60 * 60 * 1000;
        const token = generateToken(user, ttlMs);
        const url = `${req.protocol}://${req.get('host')}/access/${token}`;

        if (user && body.save) {
            const all = readAccessFile();
            const slug = user.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
            all[token] = {
                token,
                url,
                user,
                createdAt: new Date().toISOString(),
                expiresAt: Date.now() + ttlMs,
                slug
            };
            writeAccessFile(all);
        }

        res.json({ success: true, url, token });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ---------- LIST ACCESS LINKS (admin) ----------
app.get('/api/access-links', requireAdmin, (req, res) => {
    const all = readAccessFile();
    res.json({ success: true, links: Object.values(all) });
});

// ---------- ACCESS ROUTE ----------
app.get('/access/:token', (req, res) => {
    const token = req.params.token;
    const payload = verifyToken(token);
    if (!payload) {
        res.status(403).send("Invalid or expired access code.");
        return;
    }
    // Serve the 2ndchrome / vm page and include token as query so client can use autosave if needed.
    res.sendFile(path.join(PUBLIC_DIR, "2ndchrome.html"));
});

// ---------- AUTOSAVE PROFILE ----------
/*
 POST /api/save-profile
 Headers: Content-Type: application/json
 Body:
 {
   token: "<token>",
   filename: "optional-file-name.txt",
   contentBase64: "<base64...>"
 }
 Only saved links with a user will be accepted (we don't allow storing profile for unsaved tokens)
*/
app.post('/api/save-profile', (req, res) => {
    try {
        const body = req.body || {};
        const token = String(body.token || '');
        const filename = String(body.filename || 'autosave.bin');
        const contentB64 = String(body.contentBase64 || '');
        if (!token || !contentB64) {
            return res.status(400).json({ success: false, error: "token and contentBase64 required" });
        }
        // verify token and also check that it's a saved link with user
        const payload = verifyToken(token);
        if (!payload || !payload.user) {
            return res.status(403).json({ success: false, error: "Invalid token or no user associated" });
        }
        const all = readAccessFile();
        // ensure token exists in saved file (only saved links are allowed to write)
        if (!all[token]) {
            return res.status(403).json({ success: false, error: "Token not saved on server for writes" });
        }
        const slug = all[token].slug || payload.user.toLowerCase().replace(/[^a-z0-9]+/g, '-');
        const dir = path.join(PRO_USERS_DIR, slug);
        fs.mkdirSync(dir, { recursive: true });
        const ts = Date.now();
        const outPath = path.join(dir, `${ts}-${filename}`);
        const buffer = Buffer.from(contentB64, 'base64');
        fs.writeFileSync(outPath, buffer);
        res.json({ success: true, path: outPath });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ---------- INDEX returns index.html automatically via static server ----------

// ---------- ADMIN UI route (guarded on server) ----------
app.get('/admin', (req, res) => {
    if (req.session && req.session.admin) {
        res.sendFile(path.join(PUBLIC_DIR, "admin.html"));
    } else {
        // show a simple login page (index.html will link to /admin-login client code)
        res.sendFile(path.join(PUBLIC_DIR, "index.html"));
    }
});

// ---------- server creation and upgrade handling (unchanged) ----------
const server = http.createServer(app);
server.on(
    "upgrade",
    (req, socket, head) => {
        if (
            req.url &&
            req.url.startsWith(
                "/websockify"
            )
        ) {
            // existing proxyWebSocketToVNC implementation should be here from your original server.js
            // For brevity, keep the original proxyWebSocketToVNC function and usage as in your file.
            proxyWebSocketToVNC(req, socket, head);
            return;
        }
        socket.destroy();
    }
);

// rest of your shutdown/startup/watchdog/start parts go after this line.
// BE SURE to keep the existing start() and shutdown() functions you already had.

module.exports = { app, generateToken, verifyToken };
