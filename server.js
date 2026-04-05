const express = require("express");
const jwt     = require("jsonwebtoken");
const fs      = require("fs");
const path    = require("path");
const crypto  = require("crypto");

const app  = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────────────────────────────────────────────────────
//  JWT secret derivation
//  The secret is NOT stored anywhere — it is derived at runtime.
//  Clue: the app name is visible in the HTML title and footer.
//  Derivation: SHA-256( appName ) — players must discover appName from the UI,
//  then compute the hex digest themselves to forge a token.
// ─────────────────────────────────────────────────────────────────────────────
const APP_NAME   = "ultimate-revenge";           // visible in title + footer
const JWT_SECRET = crypto
  .createHash("sha256")
  .update(APP_NAME)
  .digest("hex");

// ─────────────────────────────────────────────────────────────────────────────
//  Flag — two parts
//  Part 1: returned directly after authentication (no traversal needed)
//  Part 2: stored outside the app root, requires path traversal + admin JWT
// ─────────────────────────────────────────────────────────────────────────────
const FLAG_P1 = "SECURINETS{th3_ch41n";
const FLAG_P2 = "_1s_unbre4k4bl3}";

fs.mkdirSync("/var/cache/app", { recursive: true });
fs.writeFileSync("/var/cache/app/.p2", FLAG_P2);   // p2 only — p1 served via API

// ─────────────────────────────────────────────────────────────────────────────
//  Middleware
// ─────────────────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// Rate limiting (in-memory, resets every 60 s)
const rateMap = new Map();
setInterval(() => rateMap.clear(), 60_000);

function rateLimit(req, res, next) {
  const ip    = req.ip;
  const count = (rateMap.get(ip) || 0) + 1;
  rateMap.set(ip, count);
  if (count > 30) return res.status(429).json({ error: "Slow down." });
  next();
}

// Verify any valid JWT (operator or admin)
function verifyJWT(req, res, next) {
  const auth = req.headers["authorization"] || "";
  if (!auth.startsWith("Bearer "))
    return res.status(401).json({ error: "Unauthorized" });
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET, { algorithms: ["HS256"] });
    next();
  } catch (_) {
    return res.status(403).json({ error: "Forbidden" });
  }
}

// Verify JWT AND require role === "admin"
// Intentionally leaks the current role so players know what to forge
function verifyAdmin(req, res, next) {
  const auth = req.headers["authorization"] || "";
  if (!auth.startsWith("Bearer "))
    return res.status(401).json({ error: "Unauthorized" });
  try {
    const user = jwt.verify(auth.slice(7), JWT_SECRET, { algorithms: ["HS256"] });
    if (user.role !== "admin") {
      return res.status(403).json({
        error: "Insufficient privileges",
        current_role: user.role || "none",
      });
    }
    req.user = user;
    next();
  } catch (_) {
    return res.status(403).json({ error: "Forbidden" });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Path-jail helper — resolves the path and ensures it stays within base
//  This is intentionally STILL vulnerable to double-URL-encoded traversal
//  because the caller passes `req.query.f` already decoded by Express once.
//  Players who send %252e%252e%252f get a second decode inside decodeURIComponent()
//  which produces "../" AFTER the startsWith check has already passed.
// ─────────────────────────────────────────────────────────────────────────────
const APP_ROOT = __dirname;

function resolveFile(rawInput) {
  // Block literal "../" — but NOT double-encoded sequences
  if (rawInput.includes("../"))
    return { err: "Invalid path" };

  // Block leading slash
  if (rawInput.startsWith("/"))
    return { err: "Invalid path" };

  // Decode once (players can double-encode to smuggle "../" past the check above)
  let decoded;
  try { decoded = decodeURIComponent(rawInput); }
  catch (_) { return { err: "Invalid encoding" }; }

  // Resolve against app root
  const target = path.resolve(APP_ROOT, decoded);
  return { target };
}

// ─────────────────────────────────────────────────────────────────────────────
//  Routes
// ─────────────────────────────────────────────────────────────────────────────

// Serve the SPA
app.get("/", (req, res) =>
  res.sendFile(path.join(__dirname, "public", "index.html"))
);

// ── 1. Operator login ────────────────────────────────────────────────────────
// Returns a JWT with role:"operator" and FLAG_P1 embedded in the response.
// Part 1 is given freely on login — no traversal needed.
app.post("/api/auth", rateLimit, (req, res) => {
  const { username, password } = req.body || {};
  if (username === "operator" && password === "R3v3ng3!") {
    const token = jwt.sign(
      { sub: username, role: "operator", iat: Math.floor(Date.now() / 1000) },
      JWT_SECRET,
      { algorithm: "HS256", expiresIn: "2h" }
    );
    return res.json({ token, fragment: FLAG_P1 });
  }
  return res.status(401).json({ error: "Authentication failed" });
});

// ── 2. File reader (operator) ────────────────────────────────────────────────
// Vulnerable to path traversal via double-URL-encoding.
// Blocks .p2 explicitly — players must use the admin endpoint instead.
// Extension allowlist in place, but hidden files (no extension) are allowed,
// which is how .p2 is reachable via the admin endpoint.
app.get("/api/fs/read", verifyJWT, rateLimit, (req, res) => {
  const { err, target } = resolveFile(req.query.f || "");
  if (err) return res.status(400).json({ error: err });

  // Block .p2 for non-admin users
  if (target.includes(".p2"))
    return res.status(403).json({ error: "Insufficient privileges to read this file." });

  // Extension allowlist (no extension = allowed for hidden files like .p1 which
  // is not served here anyway, but operators can read other files for recon)
  const allowed = [".txt", ".log", ".conf", ".env", ".pem"];
  const ext     = path.extname(target);
  if (ext && !allowed.includes(ext))
    return res.status(403).json({ error: "File type not permitted." });

  fs.readFile(target, "utf8", (err, data) => {
    if (err) return res.status(404).json({ error: "Not found" });
    res.send(data);
  });
});

// ── 3. Admin file reader ─────────────────────────────────────────────────────
// Requires role:"admin" JWT — only achievable by forging one using JWT_SECRET.
// The secret is SHA-256(appName) where appName is visible in the UI.
// No /api/admin/auth route exists — the ONLY way in is JWT forgery.
app.get("/api/admin/fs/read", verifyAdmin, rateLimit, (req, res) => {
  const { err, target } = resolveFile(req.query.f || "");
  if (err) return res.status(400).json({ error: err });

  // No extension restriction for admin — they can read .p2
  fs.readFile(target, "utf8", (readErr, data) => {
    if (readErr) return res.status(404).json({ error: "Not found" });
    res.send(data);
  });
});

// ── 4. System info ────────────────────────────────────────────────────────────
// Leaks process info. Intentionally does NOT reveal the secret or admin route.
// Players can use this for recon (pid, node version, uptime, their role).
app.get("/api/sys/info", verifyJWT, (req, res) => {
  try {
    const cmdline = fs
      .readFileSync("/proc/self/cmdline", "utf8")
      .replace(/\0/g, " ")
      .trim();
    res.json({
      node:    process.version,
      uptime:  process.uptime().toFixed(2),
      pid:     process.pid,
      cmdline,
      role:    req.user.role,
    });
  } catch (_) {
    res.json({ node: process.version, uptime: process.uptime().toFixed(2), role: req.user.role });
  }
});

// ── Health ────────────────────────────────────────────────────────────────────
app.get("/health", (_req, res) => res.send("OK"));

// ── 404 ───────────────────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: "Not found" }));

// ─────────────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[ultimate-revenge] listening on :${PORT}`);
});
