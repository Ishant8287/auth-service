const express = require("express");
const { signUp, login, getMe } = require("../controllers/authController");
const { protect } = require("../middlewares/authMiddleware");
const router = express.Router();

router.post("/signup", signUp);
router.post("/login", login);

//Protected routes
router.get("/me", protect, getMe);

module.exports = router;
