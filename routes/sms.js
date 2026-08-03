const express = require("express");
const router = express.Router();
const { analyzeSms } = require("../controllers/smsController");
const { protect } = require("../middleware/authMiddleware");

router.post("/analyze", protect, analyzeSms);

module.exports = router;
