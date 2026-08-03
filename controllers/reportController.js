const Scan = require("../models/Scan");

// @route GET /api/reports/summary?days=30
exports.getSummary = async (req, res) => {
  try {
    const userId = req.user._id;
    const days = Math.min(parseInt(req.query.days) || 30, 365);
    const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

    const [byType, byVerdict, trend, reasonDocs] = await Promise.all([
      Scan.aggregate([
        { $match: { user: userId } },
        { $group: { _id: "$type", count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ]),
      Scan.aggregate([
        { $match: { user: userId } },
        { $group: { _id: "$verdict", count: { $sum: 1 } } },
      ]),
      Scan.aggregate([
        { $match: { user: userId, createdAt: { $gte: since } } },
        {
          $group: {
            _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
            count: { $sum: 1 },
            dangerous: { $sum: { $cond: [{ $eq: ["$verdict", "Dangerous"] }, 1, 0] } },
          },
        },
        { $sort: { _id: 1 } },
      ]),
      Scan.find({ user: userId }).select("reasons").limit(500),
    ]);

    const reasonCounts = {};
    reasonDocs.forEach((doc) => {
      (doc.reasons || []).forEach((r) => {
        reasonCounts[r] = (reasonCounts[r] || 0) + 1;
      });
    });
    const topReasons = Object.entries(reasonCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([reason, count]) => ({ reason, count }));

    return res.status(200).json({
      success: true,
      byType,
      byVerdict,
      trend,
      topReasons,
      rangeDays: days,
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
};

// @route GET /api/reports/export.csv
exports.exportCsv = async (req, res) => {
  try {
    const scans = await Scan.find({ user: req.user._id }).sort({ createdAt: -1 });

    const escape = (val) => `"${String(val).replace(/"/g, '""')}"`;
    const header = ["Type", "Input", "Verdict", "Score", "Reasons", "Date"].join(",");
    const rows = scans.map((s) =>
      [
        escape(s.type),
        escape(s.input),
        escape(s.verdict),
        s.score,
        escape((s.reasons || []).join("; ")),
        escape(new Date(s.createdAt).toISOString()),
      ].join(",")
    );

    const csv = [header, ...rows].join("\n");

    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", `attachment; filename="scam-shield-report-${Date.now()}.csv"`);
    return res.status(200).send(csv);
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
};
