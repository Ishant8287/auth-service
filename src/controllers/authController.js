const asyncHandler = require("../utils/asyncHandler");
const AppError = require("../utils/AppError");
const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto"); // built-in Node module
const { OAuth2Client } = require("google-auth-library");
const {
  generateAccessToken,
  generateRefreshToken,
} = require("../utils/generateToken");

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Helper: set refresh token cookie
const setRefreshCookie = (res, token) => {
  res.cookie("refreshToken", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
  });
};

/*
SIGNUP
*/
exports.signUp = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    throw new AppError("Name, email and password are required", 400);
  }

  const existingUser = await User.findOne({ email });
  if (existingUser) {
    throw new AppError("User already exists", 409);
  }

  const newUser = await User.create({ name, email, password });
  newUser.password = undefined;

  return res.status(201).json({
    status: "success",
    data: newUser,
  });
});

/*
LOGIN
*/
exports.login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    throw new AppError("Email and password are required", 400);
  }

  const user = await User.findOne({ email }).select("+password");

  if (!user) {
    throw new AppError("Invalid credentials", 401);
  }

  if (!user.password) {
    throw new AppError("Please login using Google", 400);
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    throw new AppError("Invalid credentials", 401);
  }

  const accessToken = generateAccessToken(user._id);
  const refreshToken = generateRefreshToken(user._id);

  user.refreshToken = refreshToken;
  await user.save({ validateBeforeSave: false });

  setRefreshCookie(res, refreshToken);

  return res.status(200).json({
    status: "success",
    accessToken,
  });
});

/*
GET CURRENT USER
*/
exports.getMe = asyncHandler(async (req, res) => {
  return res.status(200).json({
    status: "success",
    data: req.user,
  });
});

/*
REFRESH ACCESS TOKEN
*/
exports.refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken = req.cookies.refreshToken;

  if (!incomingRefreshToken) {
    throw new AppError("Refresh token required", 401);
  }

  let decoded;
  try {
    decoded = jwt.verify(incomingRefreshToken, process.env.JWT_REFRESH_SECRET);
  } catch (err) {
    throw new AppError("Invalid or expired refresh token", 401);
  }

  const user = await User.findById(decoded.id).select("+refreshToken");

  if (!user || user.refreshToken !== incomingRefreshToken) {
    throw new AppError("Invalid refresh token", 401);
  }

  // Rotate: generate new access + refresh tokens
  const newAccessToken = generateAccessToken(user._id);
  const newRefreshToken = generateRefreshToken(user._id);

  // Invalidate old refresh token, store new one
  user.refreshToken = newRefreshToken;
  await user.save({ validateBeforeSave: false });

  setRefreshCookie(res, newRefreshToken);

  return res.status(200).json({
    status: "success",
    accessToken: newAccessToken,
  });
});

/*
GOOGLE AUTH
*/
exports.googleAuthController = asyncHandler(async (req, res) => {
  const { idToken } = req.body;

  if (!idToken) {
    throw new AppError("Google ID token is required", 400);
  }

  let payload;
  try {
    const ticket = await googleClient.verifyIdToken({
      idToken,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    payload = ticket.getPayload();
  } catch (err) {
    throw new AppError("Invalid Google token", 401);
  }

  const { email, name, sub: googleId } = payload;

  let user = await User.findOne({ email });

  if (!user) {
    user = await User.create({ name, email, googleId });
  } else {
    if (!user.googleId) {
      user.googleId = googleId;
      await user.save({ validateBeforeSave: false });
    }
  }

  const accessToken = generateAccessToken(user._id);
  const refreshToken = generateRefreshToken(user._id);

  user.refreshToken = refreshToken;
  await user.save({ validateBeforeSave: false });

  setRefreshCookie(res, refreshToken);

  return res.status(200).json({
    status: "success",
    accessToken,
  });
});

/*
LOGOUT
*/
exports.logout = asyncHandler(async (req, res) => {
  const user = req.user;

  user.refreshToken = null;
  await user.save({ validateBeforeSave: false });

  res.clearCookie("refreshToken");

  return res.status(200).json({
    status: "success",
    message: "Logged out successfully",
  });
});

/*
SET PASSWORD (Google users adding a password)
*/
exports.setPassword = asyncHandler(async (req, res) => {
  const { password } = req.body;

  if (!password) {
    throw new AppError("Password is required", 400);
  }

  const user = await User.findById(req.user._id).select("+password");

  if (user.password) {
    throw new AppError("Password already set", 400);
  }

  user.password = password;
  await user.save(); // triggers pre-save hash

  return res.status(200).json({
    status: "success",
    message: "Password set successfully",
  });
});

/*
DELETE USER (Admin only)
*/
exports.deleteUser = asyncHandler(async (req, res) => {
  const { id } = req.params;

  if (req.user._id.toString() === id) {
    throw new AppError("You cannot delete yourself", 400);
  }

  const user = await User.findById(id);
  if (!user) {
    throw new AppError("User not found", 404);
  }

  await User.findByIdAndDelete(id);

  return res.status(200).json({
    status: "success",
    message: "User deleted successfully",
  });
});

/*
FORGOT PASSWORD
*/
exports.forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  if (!email) {
    throw new AppError("Email is required", 400);
  }

  const user = await User.findOne({ email });
  if (!user) {
    throw new AppError("User not found", 404);
  }

  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  const resetURL = `${process.env.CLIENT_URL || "http://localhost:3000"}/reset-password/${resetToken}`;

  return res.status(200).json({
    status: "success",
    message: "Reset token generated. Send this via email in production.",
    ...(process.env.NODE_ENV === "development" && { resetURL }),
  });
});

/*
RESET PASSWORD
*/
exports.resetPassword = asyncHandler(async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  if (!password) {
    throw new AppError("New password is required", 400);
  }

  const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });

  if (!user) {
    throw new AppError("Token is invalid or expired", 400);
  }

  user.password = password;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  // FIX: invalidate all active sessions after password reset
  user.refreshToken = null;

  await user.save(); // triggers pre-save hash

  res.clearCookie("refreshToken");

  return res.status(200).json({
    status: "success",
    message: "Password reset successfully. Please login again.",
  });
});
