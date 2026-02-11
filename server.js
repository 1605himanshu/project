console.log("THIS SERVER FILE IS RUNNING");

require("dotenv").config();

const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");

const requestLogger = require("./middleware/logger");
const authMiddleware = require("./middleware/auth");

const app = express();
const PORT = process.env.PORT || 3000;

// In-memory storage
const loginSessions = {};
const otpStore = {};

// --------------------
// Middleware
// --------------------
app.use(requestLogger);
app.use(express.json());
app.use(cookieParser());

// --------------------
// Root Route
// --------------------
app.get("/", (req, res) => {
  return res.status(200).json({
    challenge: "Complete the Authentication Flow",
    instruction:
      "Complete the authentication flow and obtain a valid access token.",
  });
});

// --------------------
// Step 1: Login
// --------------------
app.post("/auth/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      error: "Email and password required",
    });
  }

  const loginSessionId = Math.random().toString(36).substring(2);
  const otp = Math.floor(100000 + Math.random() * 900000);

  loginSessions[loginSessionId] = {
    email,
    createdAt: Date.now(),
    expiresAt: Date.now() + 2 * 60 * 1000,
  };

  otpStore[loginSessionId] = otp;

  console.log(`OTP for ${loginSessionId}: ${otp}`);

  return res.status(200).json({
    message: "OTP sent",
    loginSessionId,
  });
});

// --------------------
// Step 2: Verify OTP
// --------------------
app.post("/auth/verify-otp", (req, res) => {
  const { loginSessionId, otp } = req.body;

  if (!loginSessionId || !otp) {
    return res.status(400).json({
      error: "loginSessionId and otp required",
    });
  }

  const session = loginSessions[loginSessionId];

  if (!session) {
    return res.status(401).json({ error: "Invalid session" });
  }

  if (Date.now() > session.expiresAt) {
    return res.status(401).json({ error: "Session expired" });
  }

  if (Number(otp) !== otpStore[loginSessionId]) {
    return res.status(401).json({ error: "Invalid OTP" });
  }

  delete otpStore[loginSessionId];

  res.cookie("session_token", loginSessionId, {
    httpOnly: true,
    secure: false,
    maxAge: 15 * 60 * 1000,
  });

  return res.status(200).json({
    message: "OTP verified",
    sessionId: loginSessionId,
  });
});

// --------------------
// Step 3: Generate JWT
// --------------------
app.post("/auth/token", (req, res) => {
  console.log("Cookies received:", req.cookies); // Debug line

  const sessionId = req.cookies.session_token;

  if (!sessionId) {
    return res
      .status(401)
      .json({ error: "Unauthorized - valid session required" });
  }

  const session = loginSessions[sessionId];

  if (!session) {
    return res.status(401).json({ error: "Invalid session" });
  }

  const secret = process.env.JWT_SECRET || "default-secret-key";

  const accessToken = jwt.sign(
    {
      email: session.email,
      sessionId: sessionId,
    },
    secret,
    { expiresIn: "15m" }
  );

  return res.status(200).json({
    access_token: accessToken,
    expires_in: 900,
  });
});

// --------------------
// Protected Route
// --------------------
app.get("/protected", authMiddleware, (req, res) => {
  return res.status(200).json({
    message: "Access granted",
    user: req.user,
    success_flag: `FLAG-${Buffer.from(
      req.user.email + "_COMPLETED_ASSIGNMENT"
    ).toString("base64")}`,
  });
});

// --------------------
// Start Server
// --------------------
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
