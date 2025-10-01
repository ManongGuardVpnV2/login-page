import express from "express";
import crypto from "crypto";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json());

let tokens = {}; // Production: use DB or Redis

// Generate a new token (demo)
function createToken() {
  const token = crypto.randomBytes(16).toString("hex");
  const expiry = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
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

// Demo: generate token
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

// Serve login page dynamically (no separate HTML file needed)
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
      <div class="w-full max-w-sm bg-white rounded-2xl shadow-lg p-6">
        <h2 class="text-2xl font-bold text-center mb-4">Access IPTV</h2>

        <button onclick="getToken()" 
          class="w-full bg-green-500 hover:bg-green-600 text-white font-semibold py-2 px-4 rounded-lg mb-4">
          Generate Token
        </button>

        <input id="tokenInput" type="password" placeholder="Enter token" 
          class="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 mb-4">

        <button onclick="login()" 
          class="w-full bg-blue-500 hover:bg-blue-600 text-white font-semibold py-2 px-4 rounded-lg">
          Login
        </button>

        <p id="errorMsg" class="text-red-500 text-sm mt-2 hidden"></p>
        <p id="demoToken" class="text-xs text-gray-600 mt-2"></p>
      </div>

      <script>
        async function getToken() {
          const res = await fetch("/generate-token");
          const data = await res.json();
          document.getElementById("demoToken").innerText = "Demo token: " + data.token;
          document.getElementById("tokenInput").value = data.token;
        }

        async function login() {
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
              // Redirect to IPTV page on success
              window.location.href = "https://tambaynoodtv.site/";
            } else {
              errorMsg.innerText = data.error;
              errorMsg.classList.remove("hidden");
            }
          } catch {
            errorMsg.innerText = "Server error. Try again.";
            errorMsg.classList.remove("hidden");
          }
        }
      </script>
    </body>
    </html>
  `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
