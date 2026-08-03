const User = require("../models/User");
const Scan = require("../models/Scan");

// @route GET /api/admin/users
// Returns every registered user with their scan counts (total + by verdict).
exports.getAllUsersWithStats = async (req, res) => {
  try {
    const [users, scanStats] = await Promise.all([
      User.find().select("-password").sort({ createdAt: -1 }),
      Scan.aggregate([
        {
          $group: {
            _id: "$user",
            total: { $sum: 1 },
            safe: { $sum: { $cond: [{ $eq: ["$verdict", "Safe"] }, 1, 0] } },
            suspicious: { $sum: { $cond: [{ $eq: ["$verdict", "Suspicious"] }, 1, 0] } },
            dangerous: { $sum: { $cond: [{ $eq: ["$verdict", "Dangerous"] }, 1, 0] } },
            lastScanAt: { $max: "$createdAt" },
          },
        },
      ]),
    ]);

    const statsByUser = Object.fromEntries(scanStats.map((s) => [s._id.toString(), s]));

    const usersWithStats = users.map((u) => {
      const stats = statsByUser[u._id.toString()];
      return {
        id: u._id,
        name: u.name,
        email: u.email,
        role: u.role,
        avatarInitial: u.avatarInitial,
        joinedAt: u.createdAt,
        totalScans: stats?.total || 0,
        safe: stats?.safe || 0,
        suspicious: stats?.suspicious || 0,
        dangerous: stats?.dangerous || 0,
        lastScanAt: stats?.lastScanAt || null,
      };
    });

    return res.status(200).json({
      success: true,
      totalUsers: users.length,
      totalScansAcrossAllUsers: scanStats.reduce((sum, s) => sum + s.total, 0),
      users: usersWithStats,
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
};
