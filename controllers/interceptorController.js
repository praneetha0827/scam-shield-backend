const Scan = require("../models/Scan");
const { analyzeRisk } = require("../utils/riskEngine");
const { riskFields } = require("../utils/scanMapper");

function compactInputSummary({ message = "", url = "", email = "", phoneNumber = "", upiId = "" }) {
  const parts = [
    message ? `Text: ${message.slice(0, 90)}${message.length > 90 ? "..." : ""}` : null,
    url ? `URL: ${url}` : null,
    email ? `Email: ${email}` : null,
    phoneNumber ? `Phone: ${phoneNumber}` : null,
    upiId ? `UPI: ${upiId}` : null,
  ].filter(Boolean);

  return parts.join(" | ") || "AI scam interceptor assessment";
}

// @route POST /api/interceptor/analyze
// body: { message, url, email, phoneNumber, upiId, notes }
exports.analyzeInterceptorInput = async (req, res) => {
  try {
    const { message = "", url = "", email = "", phoneNumber = "", upiId = "", notes = "" } = req.body;
    const combinedText = [message, url, email, phoneNumber, upiId, notes].filter(Boolean).join("\n");

    if (!combinedText.trim()) {
      return res.status(400).json({
        success: false,
        message: "Provide text, URL, email, phone number, UPI ID, or notes to analyze",
      });
    }

    const result = analyzeRisk({ text: combinedText, sourceType: "Interceptor" });

    const scan = await Scan.create({
      user: req.user._id,
      type: "Interceptor",
      input: compactInputSummary({ message, url, email, phoneNumber, upiId }),
      verdict: result.verdict,
      score: result.score,
      reasons: result.reasons,
      ...riskFields(result),
    });

    return res.status(201).json({
      success: true,
      scan,
      analysis: {
        riskScore: result.riskScore,
        riskLevel: result.riskLevel,
        scamType: result.scamType,
        attackerIntent: result.attackerIntent,
        confidence: result.confidence,
        indicators: result.indicators,
        detectedIndicators: result.detectedIndicators,
        recommendedActions: result.recommendedActions,
        entities: result.entities,
        matchedIntents: result.matchedIntents,
      },
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
};
