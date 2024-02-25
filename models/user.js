const mongoose = require("mongoose");
const { Schema } = mongoose;

const userSchema = new Schema({
  username: String, // String is shorthand for {type: String}
  email: String,
  password: String,
  secret: String,
  is2FAEnabled: String,
});

const User = new mongoose.model("User", userSchema);

module.exports = { User };
