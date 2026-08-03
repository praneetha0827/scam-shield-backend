const express = require("express");
const router = express.Router();
const { analyzeWebsiteScan } = require("../controllers/websiteController");
const { protect } = require("../middleware/authMiddleware");

router.post("/analyze", protect, analyzeWebsiteScan);

module.exports = router;
