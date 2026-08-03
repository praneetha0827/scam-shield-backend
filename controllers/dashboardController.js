const Scan = require("../models/Scan");

const SAFETY_TIPS = [
  "Never click on links from unknown senders. Always verify before you trust!",
  "Banks and government agencies never ask for OTPs over call or SMS.",
  "Check the sender's email domain carefully — scammers use lookalike domains.",
  "If an offer feels too good to be true, it almost always is.",
  "Enable two-factor authentication on all your important accounts.",
];

// @route GET /api/dashboard/stats
exports.getStats = async (req, res) => {
  try {
    const userId = req.user._id;

    const [total, safe, suspicious, dangerous] = await Promise.all([
      Scan.countDocuments({ user: userId }),
      Scan.countDocuments({ user: userId, verdict: "Safe" }),
      Scan.countDocuments({ user: userId, verdict: "Suspicious" }),
      Scan.countDocuments({ user: userId, verdict: "Dangerous" }),
    ]);

    const oneWeekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const thisWeek = await Scan.countDocuments({ user: userId, createdAt: { $gte: oneWeekAgo } });

    const pct = (n) => (total > 0 ? Math.round((n / total) * 1000) / 10 : 0);

    return res.status(200).json({
      success: true,
      stats: {
        total,
        thisWeek,
        safe: { count: safe, pct: pct(safe) },
        suspicious: { count: suspicious, pct: pct(suspicious) },
        dangerous: { count: dangerous, pct: pct(dangerous) },
      },
      tipOfTheDay: SAFETY_TIPS[new Date().getDate() % SAFETY_TIPS.length],
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
};
