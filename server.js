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

const APP_NAME = "securinets";
const JWT_SECRET = crypto
  .createHash("sha256")
  .update(`${APP_NAME}`)
  .digest("hex");

// RSA key pair
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

// Store keys at non-obvious paths
const pubHash = crypto.createHash("sha1").update(publicKey).digest("hex").slice(0, 8);
const privHash = crypto.createHash("sha1").update(privateKey).digest("hex").slice(0, 8);

const PUB_KEY_PATH = `/tmp/.cache/${pubHash}.pub`;
const PRIV_KEY_PATH = `/tmp/.cache/${privHash}.key`;

fs.mkdirSync("/tmp/.cache", { recursive: true });
fs.writeFileSync(PUB_KEY_PATH, publicKey);
fs.writeFileSync(PRIV_KEY_PATH, privateKey);

// ─────────────────────────────────────────────
//  Flag assembly
// ─────────────────────────────────────────────
const FLAG_P1 = "SECURINETS{";
const FLAG_P2 = "th3_ch41n_";
const FLAG_P3 = "1s_unbre4k4bl3}";

fs.mkdirSync("/var/cache/app", { recursive: true });
fs.writeFileSync("/var/cache/app/.p1", FLAG_P1);
fs.writeFileSync("/var/cache/app/.p2", FLAG_P2);

// ─────────────────────────────────────────────
//  Middleware
// ─────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// Manual cookie parser
app.use((req, res, next) => {
  req.cookies = {};
  const cookieHeader = req.headers.cookie;
  if (cookieHeader) {
    cookieHeader.split(';').forEach(cookie => {
      const [name, ...rest] = cookie.split('=');
      const value = rest.join('=');
      if (name && value) {
        req.cookies[name.trim()] = decodeURIComponent(value);
      }
    });
  }
  next();
});

// Rate limiting
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

// JWT verification - supports multiple algorithms
function verifyJWT(req, res, next) {
  const token = req.cookies.token || "";
  if (!token) {
    return res.status(401).json({ error: "Unauthorized - No token cookie" });
  }

  // Try RS256 first (for final admin access)
  try {
    req.user = jwt.verify(token, publicKey, { algorithms: ["RS256"] });
    req.authMethod = "RS256";
    return next();
  } catch (_) {}

  // Try HS256 (for operator and initial admin forge)
  try {
    req.user = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });
    req.authMethod = "HS256";
    return next();
  } catch (_) {}

  return res.status(403).json({ error: "Forbidden - Invalid token" });
}

// ─────────────────────────────────────────────
//  Routes
// ─────────────────────────────────────────────

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ── 1. Login ─────────────────────────────────
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
    
    res.cookie("token", token, {
      httpOnly: false,
      secure: false,
      sameSite: "lax",
      maxAge: 2 * 60 * 60 * 1000
    });
    
    return res.json({ 
      success: true, 
      token: token,
      message: "Login successful! Operator token issued."
    });
  }
  return res.status(401).json({ error: "Authentication failed" });
});

// ── 2. Get current token info ─────────────────
app.get("/api/token/info", verifyJWT, (req, res) => {
  res.json({
    user: req.user,
    auth_method: req.authMethod,
    token_cookie_exists: !!req.cookies.token
  });
});

// ── 3. File read (path traversal) ────────────
app.get("/api/fs/read", verifyJWT, rateLimit, (req, res) => {
  let file = req.query.f || "";

  if (file.includes("../")) {
    return res.status(400).json({ error: "Invalid path" });
  }

  if (file.startsWith("/")) {
    return res.status(400).json({ error: "Invalid path" });
  }

  let decoded;
  try {
    decoded = decodeURIComponent(file);
  } catch (_) {
    return res.status(400).json({ error: "Invalid encoding" });
  }

  const allowed = [".txt", ".log", ".conf", ".key", ".pub", ".pem", ".env"];
  const ext = path.extname(decoded);
  if (ext && !allowed.includes(ext)) {
    return res.status(403).json({ error: "File type not permitted" });
  }

  const base = __dirname;
  const target = path.resolve(base, decoded);

  fs.readFile(target, "utf8", (err, data) => {
    if (err) return res.status(404).json({ error: "Not found" });
    res.send(data);
  });
});

// ── 4. Admin endpoint - REQUIRES RS256 ────────
app.get("/api/admin/retrieve", verifyJWT, (req, res) => {
  const { role, clearance } = req.user || {};
  
  // Must be RS256 verified
  if (req.authMethod !== "RS256") {
    return res.status(403).json({
      error: "Algorithm mismatch",
      message: "Admin endpoint requires RS256-signed tokens",
      your_method: req.authMethod,
      required_method: "RS256"
    });
  }
  
  if (role !== "admin" || clearance !== "omega") {
    return res.status(403).json({
      error: "Insufficient clearance",
      required: { role: "admin", clearance: "omega" },
      yours: { role: role || null, clearance: clearance || null },
    });
  }
  
  return res.json({
    flag_part3: FLAG_P3,
    message: "Chain complete. You've earned it.",
  });
});

// ── 5. System info ────────────────────────────
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
      key_locations: {
        public_key_hint: `/tmp/.cache/${pubHash}.pub`,
        private_key_hint: `/tmp/.cache/${privHash}.key`
      }
    });
  } catch (_) {
    res.json({ node: process.version, uptime: process.uptime().toFixed(2) });
  }
});

app.get("/health", (req, res) => res.send("OK"));
app.use((req, res) => res.status(404).json({ error: "Not found" }));

app.listen(PORT, () => {
  console.log(`[ultimate-revenge] listening on :${PORT}`);
  console.log(`[debug] Public key: ${PUB_KEY_PATH}`);
  console.log(`[debug] Private key: ${PRIV_KEY_PATH}`);
});
