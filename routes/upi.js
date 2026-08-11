const express = require("express");
const router = express.Router();
const { assessUpiTransaction } = require("../controllers/upiController");
const { protect } = require("../middleware/authMiddleware");

router.post("/assess", protect, assessUpiTransaction);

module.exports = router;
