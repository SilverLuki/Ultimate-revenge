const express = require("express");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────────────────────
//  Key material setup
// ─────────────────────────────────────────────

// JWT secret is NOT a plain string.
// It is derived as: SHA-256( appName + ":" + PORT )
// appName is embedded in the HTML title and footer — players must notice it.
const APP_NAME = "securinets";
const JWT_SECRET = crypto
  .createHash("sha256")
  .update(`${APP_NAME}`)
  .digest("hex");

// ─────────────────────────────────────────────
//  Flag assembly (two parts only)
// ─────────────────────────────────────────────
const FLAG_P1 = "SECURINETS{";
const FLAG_P2 = "th3_ch41n_1s_unbre4k4bl3}";

// Part 1: publicly readable after authentication
// The file is at /var/cache/app/.p1
fs.mkdirSync("/var/cache/app", { recursive: true });
fs.writeFileSync("/var/cache/app/.p1", FLAG_P1);

// Part 2: admin-only file
// Same location but requires admin role to read
fs.writeFileSync("/var/cache/app/.p2", FLAG_P2);

// ─────────────────────────────────────────────
//  Middleware
// ─────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files from /app/public (docker working dir)
app.use(express.static(path.join(__dirname, "public")));

// Rate limiting state (in-memory, resets every 60s)
const rateMap = new Map();
setInterval(() => rateMap.clear(), 60000);

function rateLimit(req, res, next) {
  const ip = req.ip;
  const count = (rateMap.get(ip) || 0) + 1;
  rateMap.set(ip, count);
  if (count > 30) {
    return res.status(429).json({ error: "Slow down." });
  }
  next();
}

// JWT verification middleware — supports HS256 only
function verifyJWT(req, res, next) {
  const auth = req.headers["authorization"] || "";
  if (!auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const token = auth.slice(7);

  try {
    req.user = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });
    return next();
  } catch (_) {
    return res.status(403).json({ error: "Forbidden" });
  }
}

// Admin verification middleware
function verifyAdmin(req, res, next) {
  const auth = req.headers["authorization"] || "";
  if (!auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const token = auth.slice(7);

  try {
    const user = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });
    if (user.role !== "admin") {
      return res.status(403).json({ 
        error: "Admin access required",
        hint: "Your token role is '" + (user.role || "none") + "'. Admin credentials are different from operator credentials."
      });
    }
    req.user = user;
    return next();
  } catch (_) {
    return res.status(403).json({ error: "Forbidden" });
  }
}

// ─────────────────────────────────────────────
//  Routes
// ─────────────────────────────────────────────

// Root — serves the main SPA page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ── 1. Login (operator) ──────────────────────
// Credentials: operator / R3v3ng3!
// Returns JWT with role: "operator"
app.post("/api/auth", rateLimit, (req, res) => {
  const { username, password } = req.body || {};
  if (username === "operator" && password === "R3v3ng3!") {
    const payload = {
      sub: username,
      role: "operator",
      iat: Math.floor(Date.now() / 1000),
    };
    const token = jwt.sign(payload, JWT_SECRET, {
      algorithm: "HS256",
      expiresIn: "2h",
    });
    return res.json({ token });
  }
  return res.status(401).json({ error: "Authentication failed" });
});

// ── 1b. Admin login ──────────────────────────
// Credentials: admin / 4dm1n_S3cr3t!
// Returns JWT with role: "admin"
app.post("/api/admin/auth", rateLimit, (req, res) => {
  const { username, password } = req.body || {};
  if (username === "admin" && password === "4dm1n_S3cr3t!") {
    const payload = {
      sub: username,
      role: "admin",
      iat: Math.floor(Date.now() / 1000),
    };
    const token = jwt.sign(payload, JWT_SECRET, {
      algorithm: "HS256",
      expiresIn: "2h",
    });
    return res.json({ token, message: "Admin session established. You can now access restricted files." });
  }
  return res.status(401).json({ error: "Admin authentication failed" });
});

// ── 2. File read (public files - part 1 only) ─
// Regular authenticated users can read .p1 but NOT .p2
app.get("/api/fs/read", verifyJWT, rateLimit, (req, res) => {
  let file = req.query.f || "";

  // Filter 1: block literal "../"
  if (file.includes("../")) {
    return res.status(400).json({ error: "Invalid path" });
  }

  // Filter 2: block leading slash (absolute path)
  if (file.startsWith("/")) {
    return res.status(400).json({ error: "Invalid path" });
  }

  // Filter 3: decode once and re-check — but players can double-encode
  let decoded;
  try {
    decoded = decodeURIComponent(file);
  } catch (_) {
    return res.status(400).json({ error: "Invalid encoding" });
  }

  // Extension allowlist — but hidden files (starting with .) are not blocked
  const allowed = [".txt", ".log", ".conf", ".key", ".pem", ".env"];
  const ext = path.extname(decoded);
  if (ext && !allowed.includes(ext)) {
    return res.status(403).json({ error: "File type not permitted" });
  }

  // Block access to .p2 for non-admin users
  if (decoded.includes(".p2") || decoded.endsWith(".p2")) {
    return res.status(403).json({ 
      error: "Access denied. This file requires elevated privileges.",
      hint: "Try using admin credentials to access the second flag fragment."
    });
  }

  // Build final path from the app's working directory
  const base = __dirname;
  const target = path.resolve(base, decoded);

  fs.readFile(target, "utf8", (err, data) => {
    if (err) return res.status(404).json({ error: "Not found" });
    res.send(data);
  });
});

// ── 2b. Admin file read (restricted files - part 2) ─
// Only admin users can read .p2 and other sensitive files
app.get("/api/admin/fs/read", verifyAdmin, rateLimit, (req, res) => {
  let file = req.query.f || "";

  // Filter 1: block literal "../"
  if (file.includes("../")) {
    return res.status(400).json({ error: "Invalid path" });
  }

  // Filter 2: block leading slash (absolute path)
  if (file.startsWith("/")) {
    return res.status(400).json({ error: "Invalid path" });
  }

  let decoded;
  try {
    decoded = decodeURIComponent(file);
  } catch (_) {
    return res.status(400).json({ error: "Invalid encoding" });
  }

  // Build final path from the app's working directory
  const base = __dirname;
  const target = path.resolve(base, decoded);

  fs.readFile(target, "utf8", (err, data) => {
    if (err) return res.status(404).json({ error: "Not found" });
    // Log admin access for audit trail
    console.log(`[AUDIT] Admin ${req.user.sub} read file: ${decoded}`);
    res.send(data);
  });
});

// ── 3. System info (intentional information leak) ─
// Leaks /proc/self/cmdline — players can find the process environment
app.get("/api/sys/info", verifyJWT, (req, res) => {
  try {
    const cmdline = fs
      .readFileSync("/proc/self/cmdline", "utf8")
      .replace(/\0/g, " ")
      .trim();
    res.json({
      node: process.version,
      uptime: process.uptime().toFixed(2),
      pid: process.pid,
      cmdline,
      role: req.user.role,
      hint: "Admin users have access to /api/admin/fs/read endpoint for restricted files."
    });
  } catch (_) {
    res.json({ node: process.version, uptime: process.uptime().toFixed(2), role: req.user.role });
  }
});

// ── Health ────────────────────────────────────
app.get("/health", (req, res) => res.send("OK"));

// ── 404 fallback ──────────────────────────────
app.use((req, res) => res.status(404).json({ error: "Not found" }));

app.listen(PORT, () => {
  console.log(`[ultimate-revenge] listening on :${PORT}`);
  console.log(`[debug] JWT_SECRET derived from SHA256("${APP_NAME}:${PORT}")`);
  console.log(`[debug] Operator credentials: operator / R3v3ng3!`);
  console.log(`[debug] Admin credentials: admin / 4dm1n_S3cr3t!`);
  console.log(`[debug] Part 1 (.p1) - accessible by operator`);
  console.log(`[debug] Part 2 (.p2) - accessible ONLY by admin`);
});
