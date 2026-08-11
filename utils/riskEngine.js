const { extractEntities } = require("./entityExtractor");
const { detectIntent } = require("./intentDetector");

const RISK_THRESHOLDS = {
  LOW: [0, 24],
  MEDIUM: [25, 49],
  HIGH: [50, 74],
  CRITICAL: [75, 100],
};

const RULES = [
  {
    id: "fake_prize",
    reason: "Fake prize / lottery / lucky draw claim",
    indicator: "Prize or reward bait",
    weight: 30,
    test: ({ text }) => /\b(won|winner|lucky draw|lottery|prize|jackpot|selected)\b/i.test(text),
  },
  {
    id: "urgency",
    reason: "Urgent call to action / time pressure",
    indicator: "Urgency",
    weight: 15,
    test: ({ text }) => /\b(urgent|immediately|act now|expire|within 24 hours|last chance|hurry)\b/i.test(text),
  },
  {
    id: "short_url",
    reason: "Suspicious shortened URL",
    indicator: "Shortened URL",
    weight: 20,
    test: ({ text }) => /\b(bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd|rb\.gy)\/\S+/i.test(text),
  },
  {
    id: "financial_info",
    reason: "Requests personal or financial information",
    indicator: "Sensitive information request",
    weight: 20,
    test: ({ text }) => /\b(otp|pin|cvv|account number|password|aadhaar|card number|bank details)\b/i.test(text),
  },
  {
    id: "impersonation",
    reason: "Impersonates a bank, government, or courier service",
    indicator: "Brand or authority impersonation",
    weight: 15,
    test: ({ text }) => /\b(income tax|rbi|kyc|customs|courier|parcel held|electricity board|bank account (blocked|suspended))\b/i.test(text),
  },
  {
    id: "click_claim",
    reason: "Asks to click a link to claim/verify/unlock",
    indicator: "Link-based action request",
    weight: 15,
    test: ({ text }) => /\b(click here|click the link|verify now|claim now|unlock)\b/i.test(text),
  },
  {
    id: "money_transfer",
    reason: "Requests money transfer or advance payment",
    indicator: "Payment demand",
    weight: 20,
    test: ({ text }) => /\b(processing fee|advance payment|transfer.{0,15}(amount|money)|pay.{0,15}to (claim|unlock|release))\b/i.test(text),
  },
  {
    id: "remote_access",
    reason: "Asks to install remote access or screen-sharing software",
    indicator: "Remote access request",
    weight: 35,
    test: ({ text }) => /\b(anydesk|teamviewer|remote access|screen share|screen sharing|install this app)\b/i.test(text),
  },
  {
    id: "upi_id_present",
    reason: "Contains a UPI payment identifier",
    indicator: "UPI ID",
    weight: 12,
    test: ({ entities }) => entities.upiIds.length > 0,
  },
  {
    id: "amount_present",
    reason: "Contains a monetary amount",
    indicator: "Money amount",
    weight: 10,
    test: ({ entities }) => entities.amounts.length > 0,
  },
  {
    id: "job_fee",
    reason: "Job offer asks for registration fee or promises easy income",
    indicator: "Job scam pattern",
    weight: 45,
    test: ({ text }) => /\b(job offer|work from home|registration fee|interview fee|easy income|daily income|daily earning)\b/i.test(text),
  },
  {
    id: "investment_return",
    reason: "Promises unrealistic or guaranteed investment returns",
    indicator: "Investment scam pattern",
    weight: 45,
    test: ({ text }) => /\b(guaranteed returns|double your money|crypto profit|trading profit|risk free investment)\b/i.test(text),
  },
];

function getRiskLevel(score) {
  if (score >= RISK_THRESHOLDS.CRITICAL[0]) return "CRITICAL";
  if (score >= RISK_THRESHOLDS.HIGH[0]) return "HIGH";
  if (score >= RISK_THRESHOLDS.MEDIUM[0]) return "MEDIUM";
  return "LOW";
}

function riskLevelToVerdict(riskLevel) {
  if (riskLevel === "CRITICAL") return "Dangerous";
  if (riskLevel === "HIGH" || riskLevel === "MEDIUM") return "Suspicious";
  return "Safe";
}

function recommendedActionsFor({ riskLevel, intent, entities }) {
  const actions = [];
  if (riskLevel !== "LOW") actions.push("Do not click links or reply until you verify the source.");
  if (entities.otpReferences.length || intent.attackerIntent === "OTP Theft") actions.push("Do not share OTP, PIN, password, or card details.");
  if (entities.upiIds.length || intent.attackerIntent === "UPI Fraud" || intent.attackerIntent === "Payment Fraud") actions.push("Do not send money without confirming the recipient through a trusted channel.");
  if (entities.urls.length) actions.push("Open the official website or app manually instead of using this link.");
  if (actions.length === 0) actions.push("No major scam indicators were detected, but stay cautious with unknown senders.");
  return [...new Set(actions)];
}

function analyzeRisk({ text = "", sourceType = "Text", extraRules = [] } = {}) {
  const normalizedText = String(text || "");
  const entities = extractEntities(normalizedText);
  const intent = detectIntent(normalizedText, entities);
  const matchedRules = [...RULES, ...extraRules].filter((rule) => rule.test({ text: normalizedText, entities, sourceType }));
  const ruleScore = matchedRules.reduce((sum, rule) => sum + rule.weight, 0);
  const score = Math.min(100, Math.max(0, ruleScore + intent.intentScore || (matchedRules.length ? ruleScore : 5)));
  const riskLevel = getRiskLevel(score);
  const verdict = riskLevelToVerdict(riskLevel);
  const indicators = [...new Set([...matchedRules.map((rule) => rule.indicator), ...intent.indicators])].filter(Boolean);

  return {
    score,
    verdict,
    reasons: matchedRules.map((rule) => rule.reason),
    riskScore: score,
    riskLevel,
    scamType: intent.scamType,
    attackerIntent: intent.attackerIntent,
    confidence: Math.min(0.98, Math.max(0.2, score / 100)),
    indicators,
    detectedIndicators: indicators,
    recommendedActions: recommendedActionsFor({ riskLevel, intent, entities }),
    entities,
    matchedIntents: intent.matchedIntents,
  };
}

module.exports = {
  analyzeRisk,
  getRiskLevel,
  riskLevelToVerdict,
  RISK_THRESHOLDS,
};
