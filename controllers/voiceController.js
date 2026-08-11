const Scan = require("../models/Scan");
const { analyzeVoice } = require("../utils/scamAnalyzer");
const { riskFields } = require("../utils/scanMapper");

// @route POST /api/voice/analyze
// body: { callerNumber, transcript }
exports.analyzeVoiceScan = async (req, res) => {
  try {
    const { callerNumber, transcript } = req.body;

    if (!transcript || !transcript.trim()) {
      return res.status(400).json({ success: false, message: "Call transcript is required" });
    }

    const result = analyzeVoice({ callerNumber, transcript });
    const { score, verdict, reasons } = result;

    const inputSummary = callerNumber ? `Call from ${callerNumber}: "${transcript.slice(0, 80)}${transcript.length > 80 ? "..." : ""}"` : `"${transcript.slice(0, 100)}${transcript.length > 100 ? "..." : ""}"`;

    const scan = await Scan.create({
      user: req.user._id,
      type: "Voice",
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
