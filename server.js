import express from "express";
import crypto from "crypto";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json());

let tokens = {}; // In production: use DB or Redis for persistence

// Generate real token
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

// Generate token for user (for first time login)
app.get("/generate-token", (req, res) => {
  const { token, expiry } = createToken();
  res.json({ token, expiry });
});

// Validate token
app.post("/validate-token", (req, res) => {
  const { token } = req.body;
  if (validateToken(token)) {
    res.json({ success: true, expiry: tokens[token] });
  } else {
    res.status(400).json({ success: false, error: "Invalid or expired token" });
  }
});

// Serve login page dynamically
app.get("*", (req, res) => {
  res.send(`
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Token Login</title>
    <script src="https://cdn.tailwindcss.com"></script>
  </head>
  <body class="flex items-center justify-center min-h-screen bg-gray-100">
    <div id="loginCard" class="w-full max-w-sm bg-white rounded-2xl shadow-lg p-6">
      <h2 class="text-2xl font-bold text-center mb-4">Access IPTV</h2>

      <button id="generateBtn" 
        class="w-full bg-green-500 hover:bg-green-600 text-white font-semibold py-2 px-4 rounded-lg mb-4">
        Generate Token
      </button>

      <input id="tokenInput" type="password" placeholder="Enter token" 
        class="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 mb-4">

      <button id="loginBtn" 
        class="w-full bg-blue-500 hover:bg-blue-600 text-white font-semibold py-2 px-4 rounded-lg">
        Login
      </button>

      <p id="errorMsg" class="text-red-500 text-sm mt-2 hidden"></p>
      <p id="demoToken" class="text-xs text-gray-600 mt-2"></p>
    </div>

    <div id="successCard" class="hidden w-full max-w-sm bg-white rounded-2xl shadow-lg p-6 text-center">
      <h2 class="text-2xl font-bold mb-4">Access Granted ✅</h2>
      <p class="mb-2">Token valid for:</p>
      <p id="countdown" class="text-xl font-mono font-bold text-blue-600"></p>
    </div>

    <script>
      let expiryTime;
      let countdownInterval;

      // Generate token for user
      document.getElementById("generateBtn").onclick = async () => {
        const res = await fetch("/generate-token");
        const data = await res.json();
        document.getElementById("demoToken").innerText = "Token: " + data.token;
        document.getElementById("tokenInput").value = data.token;
      };

      // Login
      document.getElementById("loginBtn").onclick = async () => {
        const token = document.getElementById("tokenInput").value;
        const errorMsg = document.getElementById("errorMsg");
        errorMsg.classList.add("hidden");

        try {
          const res = await fetch("/validate-token", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ token })
          });
          const data = await res.json();
          if (data.success) {
            localStorage.setItem("token", token);
            localStorage.setItem("expiry", data.expiry);
            showSuccess(data.expiry);
          } else {
            errorMsg.innerText = data.error;
            errorMsg.classList.remove("hidden");
          }
        } catch {
          errorMsg.innerText = "Server error. Try again.";
          errorMsg.classList.remove("hidden");
        }
      };

      function showSuccess(expiry) {
        document.getElementById("loginCard").classList.add("hidden");
        document.getElementById("successCard").classList.remove("hidden");

        expiryTime = expiry;
        startCountdown();

        // Redirect automatically when token expires
        setTimeout(() => {
          alert("Token expired. Returning to login.");
          localStorage.removeItem("token");
          localStorage.removeItem("expiry");
          location.reload();
        }, expiryTime - Date.now());

        // Redirect immediately to IPTV
        window.location.href = "https://tambaynoodtv.site/";
      }

      function startCountdown() {
        clearInterval(countdownInterval);
        countdownInterval = setInterval(() => {
          const now = Date.now();
          const distance = expiryTime - now;

          if (distance <= 0) {
            clearInterval(countdownInterval);
            return;
          }

          const hours = Math.floor((distance / (1000 * 60 * 60)) % 24);
          const minutes = Math.floor((distance / (1000 * 60)) % 60);
          const seconds = Math.floor((distance / 1000) % 60);
          document.getElementById("countdown").innerText = \`\${hours}h \${minutes}m \${seconds}s\`;
        }, 1000);
      }

      // Restore session on reload
      window.onload = () => {
        const token = localStorage.getItem("token");
        const expiry = localStorage.getItem("expiry");
        if (token && expiry && Date.now() < parseInt(expiry)) {
          showSuccess(parseInt(expiry));
        } else {
          localStorage.removeItem("token");
          localStorage.removeItem("expiry");
        }
      };
    </script>
  </body>
  </html>
  `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(\`✅ Server running on port \${PORT}\`));
