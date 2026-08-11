const express = require("express");
const router = express.Router();
const { analyzeInterceptorInput } = require("../controllers/interceptorController");
const { protect } = require("../middleware/authMiddleware");

router.post("/analyze", protect, analyzeInterceptorInput);

module.exports = router;
