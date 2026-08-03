const express = require("express");
const router = express.Router();
const { getAllUsersWithStats } = require("../controllers/adminController");
const { protect } = require("../middleware/authMiddleware");
const { isAdmin } = require("../middleware/adminMiddleware");

router.get("/users", protect, isAdmin, getAllUsersWithStats);

module.exports = router;
