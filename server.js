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

// RSA key pair – we only need the public key for the attack
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

// Store public key at a non‑obvious path
const pkHash = crypto
  .createHash("sha1")
  .update(publicKey)
  .digest("hex")
  .slice(0, 8);
const PK_PATH = `/tmp/.cache/${pkHash}.key`;
fs.mkdirSync("/tmp/.cache", { recursive: true });
fs.writeFileSync(PK_PATH, publicKey);

// ─────────────────────────────────────────────
//  Flag assembly
// ─────────────────────────────────────────────
const FLAG_P1 = "SECURINETS{th3";
const FLAG_P2 = "_ch41n_";
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

// ─────────────────────────────────────────────
//  ALGORITHM CONFUSION VERIFICATION
//  We want: token signed with HS256 using the RSA public key
//  to be verified as RS256.
//  To do this, we first try to verify as RS256 normally.
//  If that fails, we try to verify as HS256 using the public key.
//  If THAT succeeds, we treat it as a valid RS256 token.
// ─────────────────────────────────────────────
function verifyJWT(req, res, next) {
  const token = req.cookies.token || "";
  if (!token) {
    return res.status(401).json({ error: "Unauthorized - No token cookie" });
  }

  // 1. Try normal RS256 verification (requires real RSA signature)
  try {
    req.user = jwt.verify(token, publicKey, { algorithms: ["RS256"] });
    req.authMethod = "RS256";
    return next();
  } catch (_) {}

  // 2. Algorithm confusion: try HS256 with the public key as the HMAC secret
  //    This is the attack path.
  try {
    req.user = jwt.verify(token, publicKey, { algorithms: ["HS256"] });
    // If we get here, the token was signed with HS256 using the public key.
    // We now mark it as if it were RS256 – this is the confusion!
    req.authMethod = "RS256";
    console.log("[+] Algorithm confusion: HS256+publicKey accepted as RS256");
    return next();
  } catch (_) {}

  // 3. Fallback for regular operator tokens (HS256 with JWT_SECRET)
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

// ── 1. Login (HS256 operator token) ──────────
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
      maxAge: 2 * 60 * 60 * 1000,
    });
    return res.json({
      success: true,
      token: token,
      message: "Operator token issued (HS256).",
    });
  }
  return res.status(401).json({ error: "Authentication failed" });
});

// ── 2. Token info ────────────────────────────
app.get("/api/token/info", verifyJWT, (req, res) => {
  res.json({
    user: req.user,
    auth_method: req.authMethod,
    note: req.authMethod === "RS256" 
      ? "This token is accepted as RS256 (algorithm confusion possible)."
      : "Regular operator token.",
  });
});

// ── 3. File read (path traversal) ────────────
app.get("/api/fs/read", verifyJWT, rateLimit, (req, res) => {
  let file = req.query.f || "";

  if (file.includes("../")) return res.status(400).json({ error: "Invalid path" });
  if (file.startsWith("/")) return res.status(400).json({ error: "Invalid path" });

  let decoded;
  try {
    decoded = decodeURIComponent(file);
  } catch (_) {
    return res.status(400).json({ error: "Invalid encoding" });
  }

  const allowed = [".txt", ".log", ".conf", ".key", ".pem", ".env"];
  const ext = path.extname(decoded);
  if (ext && !allowed.includes(ext)) {
    return res.status(403).json({ error: "File type not permitted" });
  }

  const target = path.resolve(__dirname, decoded);
  fs.readFile(target, "utf8", (err, data) => {
    if (err) return res.status(404).json({ error: "Not found" });
    res.send(data);
  });
});

// ── 4. Admin endpoint – requires RS256 verification (confused) ──
app.get("/api/admin/retrieve", verifyJWT, (req, res) => {
  const { role, clearance } = req.user || {};

  // Only tokens that ended up with authMethod === "RS256" are allowed
  if (req.authMethod !== "RS256") {
    return res.status(403).json({
      error: "Algorithm mismatch",
      message: "Admin endpoint requires RS256‑verified tokens. Use algorithm confusion: sign with HS256 using the RSA public key.",
      your_method: req.authMethod,
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
    message: "Algorithm confusion successful! You used the public key to forge an HS256 token that was accepted as RS256.",
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
      public_key_path: PK_PATH,
      public_key_hash: pkHash,
      attack_hint: "Sign a JWT with HS256 using the public key as the HMAC secret. The server will accept it as RS256.",
    });
  } catch (_) {
    res.json({ node: process.version, uptime: process.uptime().toFixed(2) });
  }
});

app.get("/health", (req, res) => res.send("OK"));
app.use((req, res) => res.status(404).json({ error: "Not found" }));

app.listen(PORT, () => {
  console.log(`[ultimate-revenge] listening on :${PORT}`);
  console.log(`[debug] Public key stored at ${PK_PATH}`);
});
