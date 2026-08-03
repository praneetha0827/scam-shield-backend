// Run with: node seed.js <user_email>
// Populates sample scans for a user so the dashboard has data to show.
require("dotenv").config();
const mongoose = require("mongoose");
const connectDB = require("./config/db");
const User = require("./models/User");
const Scan = require("./models/Scan");

const sampleScans = [
  {
    type: "SMS",
    input: "Congrats! You have won a lucky draw of ₹25,000. Click here to claim now http://bit.ly/xyz123",
    verdict: "Dangerous",
    score: 92,
    reasons: ["Fake prize claim", "Urgent call to action", "Suspicious shortened URL", "Requests personal/financial information"],
  },
  {
    type: "Email",
    input: "Account Security Alert - verify your account immediately",
    verdict: "Suspicious",
    score: 65,
    reasons: ["Urgency language", "Generic greeting"],
  },
  {
    type: "Website",
    input: "www.freegiftcards.com",
    verdict: "Dangerous",
    score: 90,
    reasons: ["Newly registered domain", "No HTTPS", "Known scam pattern"],
  },
  {
    type: "QR Code",
    input: "QR Data: https://bit.ly/abc",
    verdict: "Safe",
    score: 15,
    reasons: ["Verified redirect target"],
  },
  {
    type: "WhatsApp",
    input: "Check this link: http://offer...",
    verdict: "Suspicious",
    score: 60,
    reasons: ["Shortened link", "Unsolicited offer"],
  },
];

(async () => {
  const email = process.argv[2];
  if (!email) {
    console.error("Usage: node seed.js <user_email>");
    process.exit(1);
  }

  await connectDB();
  const user = await User.findOne({ email: email.toLowerCase() });
  if (!user) {
    console.error(`No user found with email ${email}. Register that user first.`);
    process.exit(1);
  }

  await Scan.deleteMany({ user: user._id });
  const docs = sampleScans.map((s) => ({ ...s, user: user._id }));
  await Scan.insertMany(docs);

  console.log(`Seeded ${docs.length} sample scans for ${email}`);
  process.exit(0);
})();
