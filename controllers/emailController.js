const Scan = require("../models/Scan");
const { analyzeEmail } = require("../utils/scamAnalyzer");
const { riskFields } = require("../utils/scanMapper");

// @route POST /api/email/analyze
// body: { senderEmail, subject, body }
exports.analyzeEmailScan = async (req, res) => {
  try {
    const { senderEmail, subject, body } = req.body;

    if (!subject?.trim() && !body?.trim()) {
      return res.status(400).json({ success: false, message: "Email subject or body is required" });
    }

    const result = analyzeEmail({ senderEmail, subject, body });
    const { score, verdict, reasons } = result;

    const inputSummary = `From: ${senderEmail || "unknown"} — ${subject || "(no subject)"}`;

    const scan = await Scan.create({
      user: req.user._id,
      type: "Email",
      input: inputSummary,
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
