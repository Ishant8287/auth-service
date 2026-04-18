const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const AppError = require("./utils/AppError");
const authRoutes = require("./routes/authRoutes");

const app = express();

app.set("trust proxy", 1);

// Security headers
app.use(helmet());

// CORS
app.use(
  cors({
    origin: process.env.CLIENT_URL || "http://localhost:3000",
    credentials: true, // required for cookies to be sent cross-origin
  }),
);

// Body Parser
app.use(express.json());
app.use(cookieParser());

// Routes
app.use("/api/auth", authRoutes);
// Root route (health check)
app.get("/", (req, res) => {
  res.json({
    status: "success",
    message: "Auth Service API is running",
  });
});

// 404 fallback
app.use((req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl}`, 404));
});

// Global error middleware
app.use((err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || "error";

  if (process.env.NODE_ENV === "development") {
    return res.status(err.statusCode).json({
      status: err.status,
      message: err.message,
      stack: err.stack,
    });
  }

  // Production — only expose operational errors
  if (err.isOperational) {
    return res.status(err.statusCode).json({
      status: err.status,
      message: err.message,
    });
  }

  // Unknown errors — don't leak details
  return res.status(500).json({
    status: "error",
    message: "Something went wrong",
  });
});

module.exports = app;
