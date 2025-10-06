const express = require("express");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const app = express();

// === Render / Local settings ===
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "replace_this_secret";
const TOKEN_NAME = "iptv_token";
const TOKEN_EXP_SECONDS = 24 * 60 * 60; // 24 hours

app.use(express.json());
app.use(cookieParser());

// === Load channels ===
function loadChannels() {
  const filePath = path.join(__dirname, "data", "channels.json");
  if (!fs.existsSync(filePath)) return [];
  try {
    const jsonData = fs.readFileSync(filePath, "utf8");
    return JSON.parse(jsonData);
  } catch (err) {
    console.error("Error parsing channels.json:", err);
    return [];
  }
}

// === Auth Middleware ===
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

// === Serve the main HTML directly from server.js ===
app.get("/", (req, res) => {
  const html = `
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>IPTV Web Panel</title>
    <style>
      body { font-family: sans-serif; background: #121212; color: #fff; text-align: center; margin: 0; padding: 2rem; }
      .login, .channels { max-width: 600px; margin: auto; }
      input, button { padding: 10px; margin: 5px; border-radius: 8px; border: none; }
      input { width: 200px; }
      button { background: #2196f3; color: #fff; cursor: pointer; }
      .channel-card { background: #1e1e1e; padding: 10px; margin: 10px; border-radius: 10px; display: inline-block; width: 180px; }
      .channel-card img { width: 100%; border-radius: 8px; }
      .watch-btn { display: block; margin-top: 6px; color: #00e676; text-decoration: none; font-weight: bold; }
    </style>
  </head>
  <body>
    <div id="loginSection" class="login">
      <h2>Enter Access Code</h2>
      <input type="text" id="accessCode" placeholder="Access code" />
      <button id="loginBtn">Login</button>
      <p id="loginMsg" style="color: red;"></p>
    </div>

    <div id="channelsSection" class="channels" style="display: none;">
      <button id="logoutBtn" style="float:right;background:#f44336;">Logout</button>
      <h2>Available Channels</h2>
      <div id="channelList"></div>
    </div>

    <script>
      async function loginUser() {
        const code = document.getElementById("accessCode").value.trim();
        const msg = document.getElementById("loginMsg");
        msg.textContent = "";
        try {
          const res = await fetch("/api/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({ accessCode: code })
          });
          const data = await res.json();
          if (!res.ok) throw new Error(data.error || "Login failed");
          document.getElementById("loginSection").style.display = "none";
          document.getElementById("channelsSection").style.display = "block";
          loadChannels();
        } catch (err) {
          msg.textContent = err.message;
        }
      }

      async function logoutUser() {
        await fetch("/api/logout", { method: "POST", credentials: "include" });
        document.getElementById("channelsSection").style.display = "none";
        document.getElementById("loginSection").style.display = "block";
      }

      async function loadChannels() {
        const list = document.getElementById("channelList");
        list.innerHTML = "<p>Loading channels...</p>";
        try {
          const res = await fetch("/api/channels", { credentials: "include" });
          if (!res.ok) {
            if (res.status === 401) {
              logoutUser();
              alert("Session expired. Please log in again.");
              return;
            }
            throw new Error("Failed to load channels");
          }
          const channels = await res.json();
          list.innerHTML = "";
          if (!channels.length) {
            list.innerHTML = "<p>No channels available.</p>";
            return;
          }
          channels.forEach((ch) => {
            const div = document.createElement("div");
            div.className = "channel-card";
            div.innerHTML = \`
              <img src="\${ch.logo}" alt="\${ch.name}" />
              <h3>\${ch.name}</h3>
              <p>\${ch.category || ""}</p>
              <a href="\${ch.manifestUri}" target="_blank" class="watch-btn">▶ Watch</a>
            \`;
            list.appendChild(div);
          });
        } catch (err) {
          list.innerHTML = "<p>Error: " + err.message + "</p>";
        }
      }

      document.addEventListener("DOMContentLoaded", () => {
        document.getElementById("loginBtn").addEventListener("click", loginUser);
        document.getElementById("logoutBtn").addEventListener("click", logoutUser);
      });
    </script>
  </body>
  </html>
  `;
  res.send(html);
});

// === Token routes ===
app.post("/api/login", (req, res) => {
  const { accessCode } = req.body;
  if (process.env.ACCESS_CODE && accessCode !== process.env.ACCESS_CODE) {
    return res.status(403).json({ error: "Invalid access code" });
  }

  const token = jwt.sign({ access: "iptv_user" }, JWT_SECRET, { expiresIn: TOKEN_EXP_SECONDS });

  res.cookie(TOKEN_NAME, token, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: TOKEN_EXP_SECONDS * 1000
  });

  res.json({ ok: true });
});

app.post("/api/logout", (req, res) => {
  res.clearCookie(TOKEN_NAME);
  res.json({ ok: true });
});

app.get("/api/channels", authMiddleware, (req, res) => {
  const channels = loadChannels();
  res.json(channels);
});

app.listen(PORT, () => console.log(`✅ IPTV Server running on port ${PORT}`));
