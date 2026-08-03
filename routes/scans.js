const express = require("express");
const router = express.Router();
const { createScan, getRecentScans, getLatestScan, getAllScans } = require("../controllers/scanController");
const { protect } = require("../middleware/authMiddleware");

router.post("/", protect, createScan);
router.get("/", protect, getAllScans);
router.get("/recent", protect, getRecentScans);
router.get("/latest", protect, getLatestScan);

module.exports = router;
