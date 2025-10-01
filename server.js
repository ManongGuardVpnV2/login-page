import express from "express";
import crypto from "crypto";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"))); // serve frontend

let tokens = {}; // in production use DB or Redis

function createToken() {
  const token = crypto.randomBytes(16).toString("hex"); // secure token
  const expiry = Date.now() + 24 * 60 * 60 * 1000; // 24h
  tokens[token] = expiry;
  return { token, expiry };
}

function refreshToken(oldToken) {
  if (!tokens[oldToken]) return null;
  const expiry = tokens[oldToken];

  if (Date.now() > expiry) {
    delete tokens[oldToken];
    return null;
  }

  const newToken = crypto.randomBytes(16).toString("hex");
  const newExpiry = Date.now() + 24 * 60 * 60 * 1000;
  delete tokens[oldToken];
  tokens[newToken] = newExpiry;

  return { token: newToken, expiry: newExpiry };
}

// --- API Routes ---

// Demo: issue a new token (in real life, send via email/SMS)
app.get("/get-token", (req, res) => {
  const { token, expiry } = createToken();
  res.json({ token, expiry });
});

// Validate token
app.post("/validate-token", (req, res) => {
  const { token } = req.body;
  if (!tokens[token]) return res.status(400).json({ success: false, error: "Invalid token" });

  const expiry = tokens[token];
  if (Date.now() > expiry) {
    delete tokens[token];
    return res.status(400).json({ success: false, error: "Token expired" });
  }

  res.json({ success: true, expiry });
});

// Refresh token
app.post("/refresh-token", (req, res) => {
  const { token } = req.body;
  const refreshed = refreshToken(token);
  if (!refreshed) return res.status(400).json({ success: false, error: "Cannot refresh" });
  res.json({ success: true, ...refreshed });
});

// Serve frontend fallback (index.html)
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ App running at http://localhost:${PORT}`));
