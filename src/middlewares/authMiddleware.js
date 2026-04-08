const asyncHandler = require("../utils/asyncHandler");
const AppError = require("../utils/AppError");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

exports.protect = asyncHandler(async (req, res, next) => {
  let token;

  const authHeader = req.headers.authorization;

  if (authHeader && authHeader.startsWith("Bearer")) {
    token = authHeader.split(" ")[1];
  }

  if (!token) {
    throw new AppError("Not authorized, no token", 401);
  }

  let decoded;

  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    throw new AppError("Invalid or expired token", 401);
  }

  const user = await User.findById(decoded.id).select("-password");

  if (!user) {
    throw new AppError("User no longer exists", 401);
  }

  req.user = user;

  next();
});
