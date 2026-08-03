const express = require("express");
const router = express.Router();
const { analyzeVoiceScan } = require("../controllers/voiceController");
const { protect } = require("../middleware/authMiddleware");

router.post("/analyze", protect, analyzeVoiceScan);

module.exports = router;
