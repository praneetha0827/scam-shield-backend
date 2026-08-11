require("dotenv").config();
const express = require("express");
const cors = require("cors");
const connectDB = require("./config/db");
const authRoutes = require("./routes/auth");
const dashboardRoutes = require("./routes/dashboard");
const scanRoutes = require("./routes/scans");
const smsRoutes = require("./routes/sms");
const emailRoutes = require("./routes/email");
const websiteRoutes = require("./routes/website");
const qrRoutes = require("./routes/qr");
const voiceRoutes = require("./routes/voice");
const reportRoutes = require("./routes/reports");
const adminRoutes = require("./routes/admin");
const upiRoutes = require("./routes/upi");
const interceptorRoutes = require("./routes/interceptor");
const callerRoutes = require("./routes/caller");

const app = express();

connectDB();

const allowedOrigins = (process.env.CLIENT_URLS || process.env.CLIENT_URL || "http://localhost:3000")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error(`CORS blocked for origin: ${origin}`));
    },
    credentials: true,
  })
);
app.use(express.json());

app.get("/api/health", (req, res) => {
  res.json({ success: true, message: "Scam Shield API is running" });
});

app.use("/api/auth", authRoutes);
app.use("/api/dashboard", dashboardRoutes);
app.use("/api/scans", scanRoutes);
app.use("/api/sms", smsRoutes);
app.use("/api/whatsapp", smsRoutes);
app.use("/api/email", emailRoutes);
app.use("/api/website", websiteRoutes);
app.use("/api/qr", qrRoutes);
app.use("/api/voice", voiceRoutes);
app.use("/api/upi", upiRoutes);
app.use("/api/interceptor", interceptorRoutes);
app.use("/api/caller", callerRoutes);
app.use("/api/reports", reportRoutes);
app.use("/api/admin", adminRoutes);

// Fallback 404
app.use((req, res) => {
  res.status(404).json({ success: false, message: "Route not found" });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
