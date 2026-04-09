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
Signup Controller
- Registers a new user
- Password hashing handled in model (pre-save hook)
*/
exports.signUp = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  // Check if user already exists
  const existingUser = await User.findOne({ email });

  if (existingUser) {
    throw new AppError("User already exists", 409);
  }

  // Create new user
  const newUser = await User.create({
    name,
    email,
    password,
  });

  res.status(201).json({
    status: "success",
    data: newUser,
  });
});

/*
Login Controller
- Verifies user credentials
- Generates access + refresh tokens
- Stores refresh token in DB
*/
exports.login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // Get user and include password
  const user = await User.findOne({ email }).select("+password");

  if (!user) {
    throw new AppError("User not found", 404);
  }

  // Compare password
  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    throw new AppError("Invalid credentials", 401);
  }

  // Generate tokens
  const accessToken = generateAccessToken(user._id);
  const refreshToken = generateRefreshToken(user._id);

  // Store refresh token in DB
  user.refreshToken = refreshToken;
  await user.save({ validateBeforeSave: false });

  res.status(200).json({
    status: "success",
    accessToken,
    refreshToken,
  });
});

/*
Get Current User
- Requires protect middleware
- Returns authenticated user data
*/
exports.getMe = asyncHandler(async (req, res) => {
  res.status(200).json({
    status: "success",
    data: req.user,
  });
});

/*
Refresh Token Controller
- Generates new access token using refresh token
*/
exports.refreshAccessToken = asyncHandler(async (req, res) => {
  const { refreshToken } = req.body;

  // Check if refresh token exists
  if (!refreshToken) {
    throw new AppError("Refresh token required", 401);
  }

  let decoded;

  try {
    // Verify refresh token
    decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
  } catch (err) {
    throw new AppError("Invalid or expired refresh token", 401);
  }

  // Find user
  const user = await User.findById(decoded.id);

  // Validate user and token match
  if (!user || user.refreshToken !== refreshToken) {
    throw new AppError("Invalid refresh token", 401);
  }

  // Generate new access token
  const newAccessToken = generateAccessToken(user._id);

  res.status(200).json({
    status: "success",
    accessToken: newAccessToken,
  });
});

/*
Logout Controller
- Removes refresh token from DB
- Requires protect middleware
*/
exports.logout = asyncHandler(async (req, res) => {
  const user = req.user;

  user.refreshToken = null;
  await user.save({ validateBeforeSave: false });

  res.status(200).json({
    status: "success",
    message: "Logged out successfully",
  });
});

/*
Delete User (Admin only)
- Deletes a user by ID
- Requires protect + restrictTo("admin")
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

  res.status(200).json({
    status: "success",
    message: "User deleted successfully",
  });
});

//forgot password controller
exports.forgotPassword = asyncHandler(async (req, res, next) => {
  const { email } = req.body;

  //find user
  const user = await User.findOne({ email });

  //if not find
  if (!user) throw new AppError("User NOT found", 404);

  //Generate reset token
  const resetToken = user.createPasswordResetToken();

  //save user and skip validation
  await user.save({ validateBeforeSave: false });

  //create reset URL
  const resetURL = `http://localhost:3000/reset-password/${resetToken}`;

  res.status(200).json({
    status: "success",
    message: "Reset token generated",
    resetURL,
  });
});

//resetPassword controller
exports.resetPassword = asyncHandler(async (req, res, next) => {
  const { token } = req.params;
  const { password } = req.body;

  const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

  //find user with token
  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });

  //If not found
  if (!user) {
    throw new AppError("Token is invalid or expired", 400);
  }

  //update password
  user.password = password;

  //remove reset fields
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;

  await user.save(); //hash pass automatically

  res.status(200).json({
    status: "success",
    message: "Password reset successfully",
  });
});
