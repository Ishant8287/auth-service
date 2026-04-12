const express = require("express");
const rateLimit = require("express-rate-limit");
const {
  signUp,
  login,
  getMe,
  logout,
  refreshAccessToken,
  deleteUser,
  forgotPassword,
  resetPassword,
  googleAuthController,
  setPassword,
} = require("../controllers/authController");
const { protect, restrictTo } = require("../middlewares/authMiddleware");

const router = express.Router();

// Rate limiter for sensitive auth routes
// Max 10 requests per 15 minutes per IP
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: {
    status: "fail",
    message: "Too many requests, please try again after 15 minutes",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Stricter limiter for password reset — prevents email bombing
const forgotPasswordLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5,
  message: {
    status: "fail",
    message: "Too many password reset requests, please try again after an hour",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Public routes
router.post("/signup", authLimiter, signUp);
router.post("/login", authLimiter, login);
router.post("/google", authLimiter, googleAuthController);
router.post("/refresh", refreshAccessToken);
router.post("/forgot-password", forgotPasswordLimiter, forgotPassword);
router.post("/reset-password/:token", authLimiter, resetPassword);

// Protected routes
router.get("/me", protect, getMe);
router.post("/logout", protect, logout);
router.post("/set-password", protect, setPassword);

// Admin only
router.delete("/delete-user/:id", protect, restrictTo("admin"), deleteUser);

module.exports = router;
