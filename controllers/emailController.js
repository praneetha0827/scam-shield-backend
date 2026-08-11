const Scan = require("../models/Scan");
const { analyzeEmail } = require("../utils/scamAnalyzer");
const { riskFields } = require("../utils/scanMapper");

// @route POST /api/email/analyze
// body: { senderEmail, replyTo, subject, body, links, headers, attachments }
exports.analyzeEmailScan = async (req, res) => {
  try {
    const { senderEmail, replyTo, subject, body, links, headers, attachments } = req.body;

    if (![subject, body, links, headers, attachments].some((value) => value?.trim())) {
      return res.status(400).json({ success: false, message: "Email content, links, headers, or attachment details are required" });
    }

    const result = analyzeEmail({ senderEmail, replyTo, subject, body, links, headers, attachments });
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
