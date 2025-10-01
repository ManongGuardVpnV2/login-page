// server.js
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3");
const bodyParser = require("body-parser");
const cors = require("cors");
const fs = require("fs");

const app = express();
const SECRET = "supersecretkey"; // CHANGE THIS in production

// Use Render writeable folder for SQLite
const DB_FILE = "/tmp/users.db";
const dbExists = fs.existsSync(DB_FILE);
const db = new sqlite3.Database(DB_FILE);

// Create users table if not exists
if (!dbExists) {
  db.run(
    "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)",
    (err) => {
      if (err) console.error("Failed to create table:", err);
      else console.log("Users table created.");
    }
  );
}

app.use(cors());
app.use(bodyParser.json());

// ----------- REGISTER -----------
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: "Missing fields" });

  try {
    const hashed = await bcrypt.hash(password, 10);
    db.run(
      "INSERT INTO users (username, password) VALUES (?, ?)",
      [username, hashed],
      function (err) {
        if (err) {
          console.error("Register error:", err.message);
          return res.status(400).json({ error: "User already exists" });
        }
        res.json({ message: "Registered successfully" });
      }
    );
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ----------- LOGIN -----------
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (!user) return res.status(400).json({ error: "Invalid username" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Invalid password" });

    const token = jwt.sign({ id: user.id, username: user.username }, SECRET, {
      expiresIn: "24h",
    });
    res.json({ message: "Login successful", token });
  });
});

// ----------- FORGOT PASSWORD (simple demo) -----------
app.post("/api/forgot", (req, res) => {
  const { username } = req.body;
  const newPass = "new123"; // In production, send email
  bcrypt.hash(newPass, 10).then((hashed) => {
    db.run(
      "UPDATE users SET password = ? WHERE username = ?",
      [hashed, username],
      function (err) {
        if (err || this.changes === 0)
          return res.status(400).json({ error: "User not found" });
        res.json({ message: `Password reset. Temporary: ${newPass}` });
      }
    );
  });
});

// ----------- JWT AUTH MIDDLEWARE -----------
function authenticate(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid or expired token" });
    req.user = user;
    next();
  });
}

// ----------- DASHBOARD (protected) -----------
app.get("/api/dashboard", authenticate, (req, res) => {
  res.json({
    message: `Welcome ${req.user.username}!`,
    secretData: "🔒 This is protected content.",
  });
});

// ----------- RENDER PORT -----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
