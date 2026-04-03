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
const APP_NAME = "ultimate-revenge";
const JWT_SECRET = crypto
  .createHash("sha256")
  .update(`${APP_NAME}:${PORT}`)
  .digest("hex");

// RSA key pair for algorithm-confusion attack (part 3)
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

// Store public key at a non-obvious path.
// The filename is the first 8 chars of the SHA1 of the public key itself.
// Players discover the name by reading /proc/self/cmdline or /proc/1/environ,
// which reveals the PID dir, from which they can list /tmp via other means.
// Actually: the file is at /tmp/.cache/<hash>.key — discoverable via /proc/self/fd/ enumeration.
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
const FLAG_P1 = "SECURINETS{";
const FLAG_P2 = "th3_ch41n_";
const FLAG_P3 = "1s_unbre4k4bl3}";

// Part 1: written to a file whose path is non-obvious.
// The file is at /var/cache/app/.p1 — not in /tmp, not obvious.
// Players read /proc/self/cwd to find the app root, then explore.
fs.mkdirSync("/var/cache/app", { recursive: true });
fs.writeFileSync("/var/cache/app/.p1", FLAG_P1);

// Part 2: written into /proc-adjacent location readable only via traversal
// It lives at ../../var/cache/app/.p2 relative to the app's static dir
fs.writeFileSync("/var/cache/app/.p2", FLAG_P2);

// Part 3: returned only by the admin endpoint after successful token confusion

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

// JWT verification middleware — supports HS256 and RS256
function verifyJWT(req, res, next) {
  const auth = req.headers["authorization"] || "";
  if (!auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const token = auth.slice(7);

  // Try HS256 first
  try {
    req.user = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });
    return next();
  } catch (_) {}

  // Try RS256
  try {
    req.user = jwt.verify(token, publicKey, { algorithms: ["RS256"] });
    return next();
  } catch (_) {}

  return res.status(403).json({ error: "Forbidden" });
}

// ─────────────────────────────────────────────
//  Routes
// ─────────────────────────────────────────────

// Root — serves the main SPA page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ── 1. Login ─────────────────────────────────
// Credentials: operator / R3v3ng3!
// JWT payload contains only username + role. No flag here.
// Part 1 must be retrieved via path traversal.
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
  // Deliberate vague error — no username/password enumeration
  return res.status(401).json({ error: "Authentication failed" });
});

// ── 2. File read (path traversal) ────────────
// Defenses that LOOK solid but aren't:
//   a) Blocks literal "../" — but not URL-decoded sequences
//   b) Restricts to extensions: .txt .log .conf .key — allows .p1 .p2 via no-extension check
//   c) Blocks absolute paths starting with "/" — but join+decode bypass works
// Players must double-encode: %252F or use ..%2F after decoding once server-side
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
  // The server calls decodeURIComponent below which handles the second decode
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

  // Build final path from the app's working directory
  const base = __dirname;
  const target = path.resolve(base, decoded);

  fs.readFile(target, "utf8", (err, data) => {
    if (err) return res.status(404).json({ error: "Not found" });
    res.send(data);
  });
});

// ── 3. Admin endpoint ────────────────────────
// Requires JWT with BOTH: role === "admin" AND clearance === "omega"
// Normal tokens only carry role="operator"
// Players must forge a token via algorithm confusion (RS256 pubkey used as HS256 secret)
app.get("/api/admin/retrieve", verifyJWT, (req, res) => {
  const { role, clearance } = req.user || {};
  if (role !== "admin" || clearance !== "omega") {
    // Reveal what claims are needed — only after a valid (but insufficient) token
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

// ── 4. System info (intentional information leak) ─
// Leaks /proc/self/cmdline — players can find the process environment
// and from there discover the /tmp/.cache/ directory indirectly
app.get("/api/sys/info", verifyJWT, (req, res) => {
  try {
    const cmdline = fs
      .readFileSync("/proc/self/cmdline", "utf8")
      .replace(/\0/g, " ")
      .trim();
    const cwd = fs.readFileSync("/proc/self/cwd").toString().trim(); // symlink — won't resolve here
    res.json({
      node: process.version,
      uptime: process.uptime().toFixed(2),
      pid: process.pid,
      cmdline,
      env_hint: "Check /proc/self/environ for more context.",
    });
  } catch (_) {
    res.json({ node: process.version, uptime: process.uptime().toFixed(2) });
  }
});

// ── Health ────────────────────────────────────
app.get("/health", (req, res) => res.send("OK"));

// ── 404 fallback ──────────────────────────────
app.use((req, res) => res.status(404).json({ error: "Not found" }));

app.listen(PORT, () => {
  console.log(`[ultimate-revenge] listening on :${PORT}`);
  console.log(`[debug] JWT_SECRET derived from SHA256("${APP_NAME}:${PORT}")`);
  console.log(`[debug] Public key stored at ${PK_PATH}`);
});
