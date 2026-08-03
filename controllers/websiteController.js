const Scan = require("../models/Scan");
const { analyzeWebsite } = require("../utils/scamAnalyzer");

// @route POST /api/website/analyze
// body: { url }
exports.analyzeWebsiteScan = async (req, res) => {
  try {
    const { url } = req.body;

    if (!url || !url.trim()) {
      return res.status(400).json({ success: false, message: "Website URL is required" });
    }

    const { score, verdict, reasons } = analyzeWebsite(url.trim());

    const scan = await Scan.create({
      user: req.user._id,
      type: "Website",
      input: url.trim(),
      verdict,
      score,
      reasons,
    });

    return res.status(201).json({ success: true, scan });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
};
