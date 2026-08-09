const express = require("express");
const router = express.Router();
const { analyzeSms, analyzeWhatsApp } = require("../controllers/smsController");
const { protect } = require("../middleware/authMiddleware");

router.post("/analyze", protect, (req, res, next) => {
  if (req.baseUrl === "/api/whatsapp") {
    return analyzeWhatsApp(req, res, next);
  }
  return analyzeSms(req, res, next);
});

module.exports = router;
