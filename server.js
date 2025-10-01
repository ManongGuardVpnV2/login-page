import express from "express";
import crypto from "crypto";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json());

let tokens = {}; // use a DB or Redis in production

// Generate token securely (this should be triggered by admin or system logic)
function createToken() {
  const token = crypto.randomBytes(3).toString("hex"); // 6-char hex
  const expiry = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
  tokens[token] = expiry;
  return { token, expiry };
}

// Example: admin or system calls this to issue a token
// DO NOT expose this endpoint to public users in production
app.post("/admin/create-token", (req, res) => {
  const { token, expiry } = createToken();
  // In production, send token via email/SMS
  res.json({ message: "Token generated and sent securely", expiry });
});

// User validation
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

app.listen(3000, () => console.log("✅ Secure server running on http://localhost:3000"));
