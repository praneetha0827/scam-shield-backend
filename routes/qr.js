const express = require("express");
const router = express.Router();
const { analyzeQr } = require("../controllers/qrController");
const { protect } = require("../middleware/authMiddleware");

router.post("/analyze", protect, analyzeQr);

module.exports = router;
