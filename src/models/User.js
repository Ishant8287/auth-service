const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      match: [/\S+@\S+\.\S+/, "Please use a valid email"],
    },

    password: {
      type: String,
      // required: [true, "password is required"],
      minlength: [8, "password must be at least 8 characters long"],
      trim: true,
      select: false,
    },

    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
    },

    refreshToken: {
      type: String,
    },
    passwordResetToken: {
      type: String,
      default: undefined,
    },
    passwordResetExpires: {
      type: Date,
      default: undefined,
    },
    googleId: {
      type: String,
    },
  },
  {
    timestamps: true,
  },
);

userSchema.methods.createPasswordResetToken = function () {
  //Generating random token
  const resetToken = crypto.randomBytes(32).toString("hex");

  //hash that token
  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  //set expiry
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

  return resetToken;
};

//Hash password before saving
userSchema.pre("save", async function () {
  if (!this.isModified("password")) return;

  this.password = await bcrypt.hash(this.password, 10);
});

module.exports = mongoose.model("User", userSchema);
