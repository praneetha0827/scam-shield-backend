// Run with: node makeAdmin.js <user_email>
require("dotenv").config();
const connectDB = require("./config/db");
const User = require("./models/User");

(async () => {
  const email = process.argv[2];
  if (!email) {
    console.error("Usage: node makeAdmin.js <user_email>");
    process.exit(1);
  }

  await connectDB();
  const user = await User.findOneAndUpdate(
    { email: email.toLowerCase() },
    { role: "admin" },
    { new: true }
  );

  if (!user) {
    console.error(`No user found with email ${email}. Register that user first.`);
    process.exit(1);
  }

  console.log(`${user.email} is now an admin.`);
  process.exit(0);
})();
