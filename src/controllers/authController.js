const asyncHandler = require("../utils/asyncHandler");
const AppError = require("../utils/AppError");
const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const {
  generateAccessToken,
  generateRefreshToken,
} = require("../utils/generateToken");

/*
SIGNUP CONTROLLER
  • Creates a new user
  • Password hashing handled via schema pre-save hook
*/
exports.signUp = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  const existingUser = await User.findOne({ email });
  if (existingUser) {
    throw new AppError("User already exists", 409);
  }

  const newUser = await User.create({
    name,
    email,
    password,
  });

  // Remove password from response
  newUser.password = undefined;

  return res.status(201).json({
    status: "success",
    data: newUser,
  });
});

/*
LOGIN CONTROLLER
  • Verifies credentials
  • Generates access + refresh tokens
  • Stores refresh token in DB and cookie
*/
exports.login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email }).select("+password");

  if (!user) {
    throw new AppError("User not found", 404);
  }

  // Block login if user is Google-only (no password set)
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

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });

  return res.status(200).json({
    status: "success",
    accessToken,
  });
});

/*
GET CURRENT USER
  • Requires protect middleware
*/
exports.getMe = asyncHandler(async (req, res) => {
  return res.status(200).json({
    status: "success",
    data: req.user,
  });
});

/*
REFRESH ACCESS TOKEN
  • Uses refresh token from cookies
  • Verifies and issues new access token
*/
exports.refreshAccessToken = asyncHandler(async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    throw new AppError("Refresh token required", 401);
  }

  let decoded;

  try {
    decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
  } catch (err) {
    throw new AppError("Invalid or expired refresh token", 401);
  }

  const user = await User.findById(decoded.id);

  if (!user || user.refreshToken !== refreshToken) {
    throw new AppError("Invalid refresh token", 401);
  }

  const newAccessToken = generateAccessToken(user._id);

  return res.status(200).json({
    status: "success",
    accessToken: newAccessToken,
  });
});

/*
GOOGLE AUTH CONTROLLER
  • Handles login/signup via Google
  • Links account if user already exists
*/
exports.googleAuthController = asyncHandler(async (req, res) => {
  const { email, name, googleId } = req.body;

  if (!email || !googleId || !name) {
    throw new AppError("Invalid Google data", 400);
  }

  let user = await User.findOne({ email });

  if (!user) {
    user = await User.create({
      name,
      email,
      googleId,
    });
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

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });

  return res.status(200).json({
    status: "success",
    accessToken,
  });
});

/*
LOGOUT CONTROLLER
  • Clears refresh token from DB and cookie
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
SET PASSWORD (FOR GOOGLE USERS)
  • Allows Google-authenticated users to set a password
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
  await user.save();

  return res.status(200).json({
    status: "success",
    message: "Password set successfully",
  });
});

/*
DELETE USER (ADMIN ONLY)
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
  • Generates reset token and stores hashed version
*/
exports.forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    throw new AppError("User not found", 404);
  }

  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  // Fixed the template literal logic here as well
  const resetURL = `http://localhost:3000/reset-password/${resetToken}`;

  return res.status(200).json({
    status: "success",
    message: "Reset token generated",
    resetURL,
  });
});

/*
RESET PASSWORD
  • Verifies token
  • Updates password
*/
exports.resetPassword = asyncHandler(async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

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

  await user.save();

  return res.status(200).json({
    status: "success",
    message: "Password reset successfully",
  });
});
