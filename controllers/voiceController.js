const Scan = require("../models/Scan");
const { analyzeVoice } = require("../utils/scamAnalyzer");

// @route POST /api/voice/analyze
// body: { callerNumber, transcript }
exports.analyzeVoiceScan = async (req, res) => {
  try {
    const { callerNumber, transcript } = req.body;

    if (!transcript || !transcript.trim()) {
      return res.status(400).json({ success: false, message: "Call transcript is required" });
    }

    const { score, verdict, reasons } = analyzeVoice({ callerNumber, transcript });

    const inputSummary = callerNumber ? `Call from ${callerNumber}: "${transcript.slice(0, 80)}${transcript.length > 80 ? "..." : ""}"` : `"${transcript.slice(0, 100)}${transcript.length > 100 ? "..." : ""}"`;

    const scan = await Scan.create({
      user: req.user._id,
      type: "Voice",
      input: inputSummary,
      verdict,
      score,
      reasons,
    });

    return res.status(201).json({ success: true, scan });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
};
