const express = require("express");
const router = express.Router();
const { analyzeCaller } = require("../controllers/callerController");
const { protect } = require("../middleware/authMiddleware");

router.post("/analyze", protect, analyzeCaller);

module.exports = router;
