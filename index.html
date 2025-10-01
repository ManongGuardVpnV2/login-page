import express from "express";
import crypto from "crypto";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json());

let tokens = {}; // In production use Redis or DB

function createToken() {
  const token = crypto.randomBytes(16).toString("hex"); // 32-char token
  const expiry = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
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

  // Issue new token with fresh expiry
  const newToken = crypto.randomBytes(16).toString("hex");
  const newExpiry = Date.now() + 24 * 60 * 60 * 1000;
  delete tokens[oldToken];
  tokens[newToken] = newExpiry;

  return { token: newToken, expiry: newExpiry };
}

// --- API Routes ---

// Admin generates token (send via email/SMS in real life)
app.post("/admin/create-token", (req, res) => {
  const { token, expiry } = createToken();
  res.json({ token, expiry }); // ⚠️ in production, don't expose token in response
});

// User validates token
app.post("/validate-token", (req, res) => {
  const { token } = req.body;
  if (!tokens[token]) {
    return res.status(400).json({ success: false, error: "Invalid token" });
  }

  const expiry = tokens[token];
  if (Date.now() > expiry) {
    delete tokens[token];
    return res.status(400).json({ success: false, error: "Token expired" });
  }

  res.json({ success: true, expiry });
});

// Refresh endpoint
app.post("/refresh-token", (req, res) => {
  const { token } = req.body;
  const refreshed = refreshToken(token);

  if (!refreshed) {
    return res.status(400).json({ success: false, error: "Cannot refresh" });
  }

  res.json({ success: true, ...refreshed });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));
