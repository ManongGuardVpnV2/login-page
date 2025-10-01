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

let tokens = {}; // production: use DB or Redis

// Generate a new token (demo purpose)
function createToken() {
  const token = crypto.randomBytes(16).toString("hex"); // 32 chars
  const expiry = Date.now() + 24 * 60 * 60 * 1000; // 24h
  tokens[token] = expiry;
  return { token, expiry };
}

// Validate token
function validateToken(token) {
  if (!tokens[token]) return false;
  if (Date.now() > tokens[token]) {
    delete tokens[token];
    return false;
  }
  return true;
}

// --- API Routes ---

// Demo: generate a token
app.get("/generate-token", (req, res) => {
  const { token, expiry } = createToken();
  res.json({ token, expiry });
});

// Validate token
app.post("/validate-token", (req, res) => {
  const { token } = req.body;
  if (validateToken(token)) {
    res.json({ success: true });
  } else {
    res.status(400).json({ success: false, error: "Invalid or expired token" });
  }
});

// Serve frontend
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));
