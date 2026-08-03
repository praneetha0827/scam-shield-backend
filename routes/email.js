const express = require("express");
const router = express.Router();
const { analyzeEmailScan } = require("../controllers/emailController");
const { protect } = require("../middleware/authMiddleware");

router.post("/analyze", protect, analyzeEmailScan);

module.exports = router;
