const express = require("express");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Setup ----------
const JWT_SECRET = "securinets"; // weak secret for part1

// Generate RSA key pair for the confusion attack
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

// Save public key to a file (accessible via path traversal)
fs.writeFileSync("/tmp/pubkey.pem", publicKey);

// Flag parts
const PART1 = "SECURINETS{web_";
const PART2 = "is_";
const PART3 = "hard_for_me}";

// Write part2 to a location outside the app (for path traversal)
fs.writeFileSync("/tmp/flag_part2.txt", PART2);

// ---------- Middleware ----------
// Verify JWT – supports both HS256 and RS256 (vulnerable to algorithm confusion)
function verifyJWT(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing token" });
  }
  const token = auth.split(" ")[1];

  // First try to verify as HS256 (with weak secret)
  try {
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });
    req.user = decoded;
    return next();
  } catch (e) {}

  // Then try RS256 (using the public key from memory)
  try {
    const decoded = jwt.verify(token, publicKey, { algorithms: ["RS256"] });
    req.user = decoded;
    return next();
  } catch (e) {}

  return res.status(403).json({ error: "Invalid token" });
}

// Track brute‑force attempts for decoy
let failedAttempts = 0;
setInterval(() => {
  failedAttempts = 0;
}, 60000);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ---------- Routes ----------
app.get("/", (req, res) => {
  res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Securinets | Triple Threat</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: 'Segoe UI', 'Poppins', monospace;
                    background: linear-gradient(135deg, #0a0f2a 0%, #1a0f2e 100%);
                    min-height: 100vh;
                    color: #e0e0ff;
                    padding: 2rem;
                }
                .container {
                    max-width: 1000px;
                    margin: 0 auto;
                    backdrop-filter: blur(10px);
                    background: rgba(10, 15, 42, 0.6);
                    border-radius: 2rem;
                    border: 1px solid rgba(100, 80, 200, 0.3);
                    padding: 2rem;
                }
                h1 {
                    background: linear-gradient(135deg, #4a6eff, #9b4dff);
                    -webkit-background-clip: text;
                    background-clip: text;
                    color: transparent;
                    text-align: center;
                }
                .card {
                    background: rgba(20, 25, 55, 0.7);
                    border-radius: 1rem;
                    padding: 1.5rem;
                    margin: 1.5rem 0;
                    border: 1px solid #4a6eff;
                }
                input, button {
                    background: rgba(0,0,0,0.4);
                    border: 1px solid #4a6eff;
                    padding: 0.7rem;
                    border-radius: 0.5rem;
                    color: white;
                    margin: 0.5rem;
                }
                button {
                    background: linear-gradient(135deg, #4a6eff, #9b4dff);
                    cursor: pointer;
                }
                .footer {
                    text-align: center;
                    margin-top: 2rem;
                    font-size: 0.8rem;
                    color: #6a6a9a;
                }
                pre {
                    background: rgba(0,0,0,0.5);
                    padding: 0.5rem;
                    border-radius: 0.5rem;
                    overflow-x: auto;
                }
            </style>
        </head>
        <body>
        <div class="container">
            <h1>🔐 Securinets Triple Threat</h1>
            <p>Three vulnerabilities, one flag. Only true skills work.</p>
            
            <div class="card">
                <h3>🔑 Login (JWT)</h3>
                <input type="text" id="username" placeholder="Username" value="alice">
                <input type="password" id="password" placeholder="Password" value="password">
                <button onclick="login()">Get JWT</button>
                <pre id="jwtResult"></pre>
            </div>
            
            <div class="card">
                <h3>📁 Read File (requires JWT)</h3>
                <input type="text" id="filename" placeholder="e.g.,flag_part2.txt">
                <button onclick="readFile()">Read</button>
                <pre id="fileResult"></pre>
                <small style="color: #6a6a9a;">💡 Hint: Temporary files.</small>
            </div>

            <div class="card">
                <h3>👑 Admin Flag (requires JWT with role=admin)</h3>
                <button onclick="getAdminFlag()">Get Flag Part 3</button>
                <pre id="adminResult"></pre>
                <small style="color: #6a6a9a;">⚙️ Tip: The same key can be used in different signing algorithms. Public keys can be found via the Read File feature. Public keys sometimes end with .pem</small>
            </div>
            
            <div class="footer">
                Securinets Revenge CTF | Task makers become task takers
            </div>
        </div>
        
        <script>
            let token = '';
            async function login() {
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                const data = await res.json();
                if (data.token) {
                    token = data.token;
                    document.getElementById('jwtResult').innerText = 'Token: ' + token;
                } else {
                    document.getElementById('jwtResult').innerText = 'Error: ' + data.error;
                }
            }
            
            async function readFile() {
                const filename = document.getElementById('filename').value;
                const res = await fetch('/api/read?file=' + encodeURIComponent(filename), {
                    headers: { 'Authorization': 'Bearer ' + token }
                });
                const text = await res.text();
                document.getElementById('fileResult').innerText = text;
            }
            
            async function getAdminFlag() {
                const res = await fetch('/api/admin/flag', {
                    headers: { 'Authorization': 'Bearer ' + token }
                });
                const data = await res.json();
                document.getElementById('adminResult').innerText = JSON.stringify(data, null, 2);
            }
        </script>
        </body>
        </html>
    `);
});

// ---------- Vulnerable endpoints ----------

// 1. JWT login – returns token with part1 in payload
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  if (username === "alice" && password === "password") {
    const payload = {
      username: "alice",
      role: "user",
      flag_part1: PART1,
    };
    const token = jwt.sign(payload, JWT_SECRET, {
      algorithm: "HS256",
      expiresIn: "1h",
    });
    return res.json({ token });
  }
  return res.status(401).json({ error: "Invalid credentials" });
});

// Decoy for brute‑force attempts
app.use((req, res, next) => {
  const auth = req.headers.authorization;
  if (auth && auth.startsWith("Bearer ")) {
    const token = auth.split(" ")[1];
    try {
      jwt.verify(token, JWT_SECRET);
    } catch (err) {
      failedAttempts++;
      if (failedAttempts > 10) {
        return res.status(429).json({
          error:
            "Too many invalid tokens. Decoy flag: SECURINETS{ya_gadour_karahtni_fi_JWT}",
        });
      }
    }
  }
  next();
});

// 2. Path traversal – requires any valid JWT
app.get("/api/read", verifyJWT, (req, res) => {
  let file = req.query.file;
  if (!file) return res.status(400).send("Missing file parameter");
  // VULNERABLE: direct path join allows ../ traversal
  const filePath = path.join(__dirname, file);
  fs.readFile(filePath, "utf8", (err, data) => {
    if (err) return res.status(404).send("File not found");
    res.send(data);
  });
});

// 3. Admin flag endpoint – requires JWT with role=admin (using algorithm confusion)
app.get("/api/admin/flag", verifyJWT, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin only" });
  }
  // Return the third flag part
  return res.json({ flag_part3: PART3 });
});

// Optional: endpoint to get the public key (but it's also readable via path traversal)
app.get("/pubkey.pem", (req, res) => {
  res.send(publicKey);
});

// Health check
app.get("/health", (req, res) => res.send("OK"));

app.listen(PORT, () => {
  console.log(`🔥 Triple Threat running on port ${PORT}`);
  console.log(`💀 JWT secret: ${JWT_SECRET}`);
  console.log(`📁 Public key available via path traversal at /tmp/pubkey.pem`);
});
