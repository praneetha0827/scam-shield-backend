const Scan = require("../models/Scan");
const { analyzeText } = require("../utils/scamAnalyzer");

// @route POST /api/sms/analyze
// body: { message: string }
exports.analyzeSms = async (req, res) => {
  try {
    const { message } = req.body;

    if (!message || !message.trim()) {
      return res.status(400).json({ success: false, message: "SMS message text is required" });
    }

    const { score, verdict, reasons } = analyzeText(message);

    const scan = await Scan.create({
      user: req.user._id,
      type: "SMS",
      input: message.trim(),
      verdict,
      score,
      reasons,
    });

    return res.status(201).json({ success: true, scan });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
};
