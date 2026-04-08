const asyncHandler = require("../utils/asyncHandler");
const AppError = require("../utils/AppError");
const User = require("../models/User");
const bcrypt = require("bcryptjs");
const { accessToken } = require("../utils/generateToken");
const { refreshToken } = require("../utils/generateToken");

//Sign up
exports.signUp = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  const foundUser = await User.findOne({ email });

  if (foundUser) {
    throw new AppError("User already exists", 409);
  }

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

//login
exports.login = asyncHandler(async (req, res, next) => {
  //get data
  const { email, password } = req.body;

  //foundUser or not ?
  const foundUser = await User.findOne({ email });

  //if not
  if (!foundUser) {
    throw new AppError("User not found", 404);
  }

  //if yes
  //Check password
  const isMatch = await bcrypt.compare(password, foundUser.password);

  //Now if pass not match
  if (!isMatch) {
    throw new AppError("Re-enter password , password does not match");
  }

  //If match then generate token
  const accessToken = accessToken(foundUser._id);
  const refreshToken = refreshToken(foundUser._id);

  //if match
  return res.status(200).json({
    status: "success",
    accessToken,
    refreshToken,
  });
});

//get me
exports.getMe = asyncHandler(async (req, res, next) => {
  res.status(200).json({
    status: "success",
    data: req.user,
  });
});

//Generate refresh token using access token
exports.refreshToken = asyncHandler(async (req, res, next) => {
  //Get refreshToken
  const { refreshToken } = req.body;

  //if we don't have refresh token
  if (!refreshToken) {
    throw new AppError("Refresh token not found", 401);
  }

  //If yes
  const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

  //Is user exists with that payload(id) comes after decoded
  const foundUser = await User.findById(foundUser._id);

  //If not found
  if (!foundUser || foundUser.refreshToken !== refreshToken) {
    throw new AppError("User not found", 401);
  }

  const newAccessToken = accessToken(foundUser._id);
F
  res.status(200).json({
    status: "success",
    accessToken : newAccessToken
  })
});
