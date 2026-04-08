const mongoose = require("mongoose");

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("DB connected successfully");
  } catch (error) {
    console.log("DB connection failed ", error.message);
    process.exit(1);
  }
};

module.exports = connectDB;
