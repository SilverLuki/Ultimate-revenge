const express = require("express");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const APP_NAME = "securinets";
const JWT_SECRET = crypto
  .createHash("sha256")
  .update(`${APP_NAME}`)
  .digest("hex");

// Generate RSA key pair
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

// Store public key
const pkHash = crypto.createHash("sha1").update(publicKey).digest("hex").slice(0, 8);
const PK_PATH = `/tmp/.cache/${pkHash}.key`;
fs.mkdirSync("/tmp/.cache", { recursive: true });
fs.writeFileSync(PK_PATH, publicKey);

// Flags
const FLAG_P1 = "SECURINETS{";
const FLAG_P2 = "th3_ch41n_";
const FLAG_P3 = "1s_unbre4k4bl3}";

fs.mkdirSync("/var/cache/app", { recursive: true });
fs.writeFileSync("/var/cache/app/.p1", FLAG_P1);
fs.writeFileSync("/var/cache/app/.p2", FLAG_P2);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// Cookie parser
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

// SIMPLE VERIFICATION - Accepts tokens signed with:
// 1. JWT_SECRET (HS256) - for operator
// 2. Public key as HMAC secret (HS256) - for admin (THIS IS THE VULNERABILITY)
function verifyJWT(req, res, next) {
  const token = req.cookies.token || "";
  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  // Try regular operator token (HS256 with JWT_SECRET)
  try {
    req.user = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });
    req.authMethod = "HS256_JWT_SECRET";
    return next();
  } catch (_) {}

  // VULNERABILITY: Accept tokens signed with the PUBLIC KEY as HMAC secret
  // This is the intended attack vector for P3
  try {
    req.user = jwt.verify(token, publicKey, { algorithms: ["HS256"] });
    req.authMethod = "HS256_PUBLIC_KEY";
    console.log("[+] Token accepted using public key as HMAC secret!");
    return next();
  } catch (_) {}

  return res.status(403).json({ error: "Forbidden" });
}

// Routes
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Login
app.post("/api/auth", rateLimit, (req, res) => {
  const { username, password } = req.body || {};
  if (username === "operator" && password === "R3v3ng3!") {
    const payload = { sub: username, role: "operator" };
    const token = jwt.sign(payload, JWT_SECRET, { algorithm: "HS256", expiresIn: "2h" });
    res.cookie("token", token, { httpOnly: false, maxAge: 2 * 60 * 60 * 1000 });
    return res.json({ success: true, token });
  }
  return res.status(401).json({ error: "Authentication failed" });
});

// Token info
app.get("/api/token/info", verifyJWT, (req, res) => {
  res.json({ user: req.user, auth_method: req.authMethod });
});

// File read with path traversal
app.get("/api/fs/read", verifyJWT, rateLimit, (req, res) => {
  let file = req.query.f || "";
  
  if (file.includes("../")) return res.status(400).json({ error: "Invalid path" });
  if (file.startsWith("/")) return res.status(400).json({ error: "Invalid path" });
  
  let decoded;
  try { decoded = decodeURIComponent(file); } catch (_) { return res.status(400).json({ error: "Invalid encoding" }); }
  
  const allowed = [".txt", ".log", ".conf", ".key", ".pem", ".env"];
  const ext = path.extname(decoded);
  if (ext && !allowed.includes(ext)) return res.status(403).json({ error: "File type not permitted" });
  
  const target = path.resolve(__dirname, decoded);
  fs.readFile(target, "utf8", (err, data) => {
    if (err) return res.status(404).json({ error: "Not found" });
    res.send(data);
  });
});

// Admin endpoint - requires token signed with PUBLIC KEY
app.get("/api/admin/retrieve", verifyJWT, (req, res) => {
  const { role, clearance } = req.user || {};
  
  // Must be signed with the public key (not the regular JWT_SECRET)
  if (req.authMethod !== "HS256_PUBLIC_KEY") {
    return res.status(403).json({
      error: "Insufficient privileges",
      message: "This endpoint requires a token signed with the RSA public key",
      hint: "Read the public key via path traversal and use it as an HMAC secret with HS256"
    });
  }
  
  if (role !== "admin" || clearance !== "omega") {
    return res.status(403).json({
      error: "Insufficient clearance",
      required: { role: "admin", clearance: "omega" }
    });
  }
  
  return res.json({ flag_part3: FLAG_P3, message: "Chain complete!" });
});

// System info
app.get("/api/sys/info", verifyJWT, (req, res) => {
  res.json({
    pid: process.pid,
    public_key_path: PK_PATH,
    public_key_hash: pkHash,
    hint: "Use path traversal to read the public key, then use it with HS256 to forge an admin token"
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Public key: ${PK_PATH}`);
});
