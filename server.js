import express from "express";
import crypto from "crypto";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json());

let tokens = {}; // replace with DB/Redis in production

// Generate a token (in real use, send via email/SMS, not directly in response)
app.post("/generate-token", (req, res) => {
  const token = crypto.randomBytes(3).toString("hex"); // 6-char hex
  const expiry = Date.now() + 24 * 60 * 60 * 1000; // 24h
  tokens[token] = expiry;

  // For demo we return it directly
  res.json({ token, expiry });
});

// Validate token
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

app.listen(3000, () => console.log("✅ Server running on http://localhost:3000"));
