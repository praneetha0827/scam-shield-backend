const Scan = require("../models/Scan");
const { analyzeWebsite } = require("../utils/scamAnalyzer");
const { riskFields } = require("../utils/scanMapper");

// @route POST /api/website/analyze
// body: { url }
exports.analyzeWebsiteScan = async (req, res) => {
  try {
    const { url } = req.body;

    if (!url || !url.trim()) {
      return res.status(400).json({ success: false, message: "Website URL is required" });
    }

    const result = analyzeWebsite(url.trim());
    const { score, verdict, reasons } = result;

    const scan = await Scan.create({
      user: req.user._id,
      type: "Website",
      input: url.trim(),
      verdict,
      score,
      reasons,
      ...riskFields(result),
    });

    return res.status(201).json({ success: true, scan });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
};
