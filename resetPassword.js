// Run with: node resetPassword.js <user_email> <new_password>
require("dotenv").config();
const connectDB = require("./config/db");
const User = require("./models/User");

(async () => {
  const email = process.argv[2];
  const newPassword = process.argv[3];

  if (!email || !newPassword) {
    console.error("Usage: node resetPassword.js <user_email> <new_password>");
    process.exit(1);
  }
  if (newPassword.length < 6) {
    console.error("Password must be at least 6 characters.");
    process.exit(1);
  }

  await connectDB();
  const user = await User.findOne({ email: email.toLowerCase() });

  if (!user) {
    console.error(`No user found with email ${email}.`);
    process.exit(1);
  }

  user.password = newPassword; // pre-save hook in User model hashes this automatically
  await user.save();

  console.log(`Password for ${user.email} has been reset.`);
  process.exit(0);
})();
