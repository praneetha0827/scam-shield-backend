const Scan = require("../models/Scan");
const { analyzeCallerImpersonation } = require("../utils/scamAnalyzer");
const { riskFields } = require("../utils/scanMapper");

// @route POST /api/caller/analyze
// body: { callerNumber, claimedOrganization, context, unknownCaller }
exports.analyzeCaller = async (req, res) => {
  try {
    const { callerNumber = "", claimedOrganization = "", context = "", unknownCaller = true } = req.body;

    if (!callerNumber.trim() && !claimedOrganization.trim() && !context.trim()) {
      return res.status(400).json({
        success: false,
        message: "Provide caller number, claimed organization, or call context",
      });
    }

    const result = analyzeCallerImpersonation({
      callerNumber: callerNumber.trim(),
      claimedOrganization: claimedOrganization.trim(),
      context: context.trim(),
      unknownCaller: Boolean(unknownCaller),
    });

    const input = [
      callerNumber ? `Caller: ${callerNumber}` : null,
      claimedOrganization ? `Claims: ${claimedOrganization}` : null,
      context ? `Context: ${context.slice(0, 90)}${context.length > 90 ? "..." : ""}` : null,
    ]
      .filter(Boolean)
      .join(" | ");

    const scan = await Scan.create({
      user: req.user._id,
      type: "Caller",
      input,
      verdict: result.verdict,
      score: result.score,
      reasons: result.reasons,
      ...riskFields(result),
    });

    return res.status(201).json({
      success: true,
      scan,
      callerRisk: {
        riskScore: result.riskScore,
        riskLevel: result.riskLevel,
        scamType: result.scamType,
        attackerIntent: result.attackerIntent,
        confidence: result.confidence,
        indicators: result.indicators,
        reasons: result.reasons,
        recommendedAction: result.recommendedAction,
        recommendedActions: result.recommendedActions,
        entities: result.entities,
      },
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
};
