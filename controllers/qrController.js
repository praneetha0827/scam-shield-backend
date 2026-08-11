const Scan = require("../models/Scan");
const { analyzeText, analyzeWebsite } = require("../utils/scamAnalyzer");
const { riskFields } = require("../utils/scanMapper");

const URL_PATTERN = /^(https?:\/\/|www\.)/i;

// @route POST /api/qr/analyze
// body: { qrData } — the decoded text/URL from a QR code (decoding happens client-side)
exports.analyzeQr = async (req, res) => {
  try {
    const { qrData } = req.body;

    if (!qrData || !qrData.trim()) {
      return res.status(400).json({ success: false, message: "Decoded QR data is required" });
    }

    const data = qrData.trim();
    const isUrl = URL_PATTERN.test(data) || /\.[a-z]{2,}(\/|$)/i.test(data);

    const result = isUrl ? analyzeWebsite(data) : analyzeText(data);
    const { score, verdict, reasons } = result;

    const scan = await Scan.create({
      user: req.user._id,
      type: "QR Code",
      input: `QR Data: ${data}`,
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
