const Scan = require("../models/Scan");
const { analyzeText } = require("../utils/scamAnalyzer");
const { riskFields } = require("../utils/scanMapper");

const analyzeMessage = (type, requiredMessage) => async (req, res) => {
  try {
    const { message } = req.body;

    if (!message || !message.trim()) {
      return res.status(400).json({ success: false, message: requiredMessage });
    }

    const result = analyzeText(message);
    const { score, verdict, reasons } = result;

    const scan = await Scan.create({
      user: req.user._id,
      type,
      input: message.trim(),
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

// @route POST /api/sms/analyze
// body: { message: string }
exports.analyzeSms = analyzeMessage("SMS", "SMS message text is required");

// @route POST /api/whatsapp/analyze
// body: { message: string }
exports.analyzeWhatsApp = analyzeMessage("WhatsApp", "WhatsApp message text is required");
