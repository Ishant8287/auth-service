const express = require("express");
const {
  signUp,
  login,
  getMe,
  logout,
  refreshAccessToken,
  deleteUser,
  forgotPassword,
  resetPassword,
} = require("../controllers/authController");
const { protect, restrictTo } = require("../middlewares/authMiddleware");
const router = express.Router();

router.post("/signup", signUp);
router.post("/login", login);

//Protected routes
router.get("/me", protect, getMe);
router.post("/logout", protect, logout);

//refresh token route
router.post("/refresh", refreshAccessToken);

//delete
router.delete("/delete-user/:id", protect, restrictTo("admin"), deleteUser);

//forgot password
router.post("/forgot-password", forgotPassword);

//reset pass
router.post("/reset-password/:token", resetPassword);

module.exports = router;
