const Scan = require("../models/Scan");
const { analyzeUpiTransaction } = require("../utils/scamAnalyzer");
const { riskFields } = require("../utils/scanMapper");

// @route POST /api/upi/assess
// body: { upiId, recipient, amount, context, firstTimeRecipient }
exports.assessUpiTransaction = async (req, res) => {
  try {
    const { upiId, recipient, amount, context, firstTimeRecipient } = req.body;

    if (!upiId?.trim() && !recipient?.trim() && !amount && !context?.trim()) {
      return res.status(400).json({
        success: false,
        message: "Provide at least a UPI ID, recipient, amount, or payment context",
      });
    }

    const result = analyzeUpiTransaction({
      upiId: upiId?.trim(),
      recipient: recipient?.trim(),
      amount,
      context: context?.trim(),
      firstTimeRecipient: Boolean(firstTimeRecipient),
    });

    const input = [
      upiId ? `UPI: ${upiId}` : null,
      recipient ? `Recipient: ${recipient}` : null,
      amount ? `Amount: ${amount}` : null,
    ]
      .filter(Boolean)
      .join(" | ");

    const scan = await Scan.create({
      user: req.user._id,
      type: "UPI",
      input: input || "UPI transaction assessment",
      verdict: result.verdict,
      score: result.score,
      reasons: result.reasons,
      ...riskFields(result),
    });

    return res.status(201).json({
      success: true,
      scan,
      assessment: {
        riskScore: result.riskScore,
        riskLevel: result.riskLevel,
        recipientRisk: result.recipientRisk,
        reasons: result.reasons,
        recommendedAction: result.recommendedAction,
        recommendedActions: result.recommendedActions,
        scamType: result.scamType,
        attackerIntent: result.attackerIntent,
        confidence: result.confidence,
        entities: result.entities,
      },
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
};
