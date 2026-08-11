const Scan = require("../models/Scan");

// @route POST /api/scans
// Generic scan-record creator. Individual scanner modules (SMS, Email, etc.)
// will call their own analysis logic and then save the result via this shape.
exports.createScan = async (req, res) => {
  try {
    const { type, input, verdict, score, reasons, riskLevel, scamType, attackerIntent, confidence, indicators, recommendedActions, entities } = req.body;

    if (!type || !input || !verdict || score === undefined) {
      return res.status(400).json({ success: false, message: "type, input, verdict and score are required" });
    }

    const scan = await Scan.create({
      user: req.user._id,
      type,
      input,
      verdict,
      score,
      reasons: reasons || [],
      riskLevel,
      scamType,
      attackerIntent,
      confidence,
      indicators: indicators || [],
      recommendedActions: recommendedActions || [],
      entities: entities || {},
    });

    return res.status(201).json({ success: true, scan });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
};

// @route GET /api/scans/recent?limit=5
exports.getRecentScans = async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 5, 50);
    const scans = await Scan.find({ user: req.user._id }).sort({ createdAt: -1 }).limit(limit);
    return res.status(200).json({ success: true, scans });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
};

// @route GET /api/scans/latest — single most recent scan, for the "Recent Scan Result" panel
exports.getLatestScan = async (req, res) => {
  try {
    const scan = await Scan.findOne({ user: req.user._id }).sort({ createdAt: -1 });
    return res.status(200).json({ success: true, scan: scan || null });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
};

// @route GET /api/scans — full paginated history (used by History module later)
exports.getAllScans = async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const filter = { user: req.user._id };
    if (req.query.type) filter.type = req.query.type;
    if (req.query.verdict) filter.verdict = req.query.verdict;

    const [scans, count] = await Promise.all([
      Scan.find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit),
      Scan.countDocuments(filter),
    ]);

    return res.status(200).json({
      success: true,
      scans,
      pagination: { page, limit, total: count, pages: Math.ceil(count / limit) },
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
};
