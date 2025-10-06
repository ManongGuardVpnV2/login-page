const express = require("express");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = process.env.PORT || 3000;

// Token settings
const JWT_SECRET = process.env.JWT_SECRET || "replace_this_secret";
const TOKEN_NAME = "iptv_token";
const TOKEN_EXP_SECONDS = 24 * 60 * 60; // 24 hours

app.use(express.json());
app.use(cookieParser());
app.use(express.static("public"));

// Load channels
function loadChannels() {
  const file = path.join(__dirname, "data", "channels.json");
  if (!fs.existsSync(file)) return [];
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

// Middleware to verify token
function authMiddleware(req, res, next) {
  const token = req.cookies[TOKEN_NAME];
  if (!token) return res.status(401).json({ error: "No token" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// === Routes ===

// Generate token (no password needed)
app.post("/api/login", (req, res) => {
  const { accessCode } = req.body;

  // Optional: simple shared code for minimal protection
  if (accessCode !== process.env.ACCESS_CODE && process.env.ACCESS_CODE) {
    return res.status(403).json({ error: "Invalid access code" });
  }

  const token = jwt.sign({ access: "iptv_user" }, JWT_SECRET, {
    expiresIn: TOKEN_EXP_SECONDS
  });

  res.cookie(TOKEN_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: TOKEN_EXP_SECONDS * 1000
  });

  res.json({ ok: true, expiresIn: TOKEN_EXP_SECONDS });
});

// Logout (clear token)
app.post("/api/logout", (req, res) => {
  res.clearCookie(TOKEN_NAME);
  res.json({ ok: true });
});

// Get channels (protected)
app.get("/api/channels", authMiddleware, (req, res) => {
  const channels = loadChannels();
  res.json(channels);
});

app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
