const INTENTS = [
  {
    intent: "OTP Theft",
    scamType: "OTP Theft",
    weight: 28,
    indicators: ["OTP request"],
    patterns: [/\botp\b/i, /\bone[-\s]?time password\b/i, /\bverification code\b/i],
  },
  {
    intent: "Credential Theft",
    scamType: "Credential Phishing",
    weight: 26,
    indicators: ["Credential request"],
    patterns: [/\bpassword\b/i, /\blogin\b/i, /\bverify.{0,20}(account|identity|details)\b/i, /\bupdate.{0,20}(kyc|account|profile)\b/i],
  },
  {
    intent: "Banking Phishing",
    scamType: "Banking Phishing",
    weight: 24,
    indicators: ["Banking impersonation"],
    patterns: [/\b(bank|rbi|hdfc|icici|sbi|axis|kotak|account blocked|account suspended|kyc)\b/i],
  },
  {
    intent: "UPI Fraud",
    scamType: "UPI Payment Scam",
    weight: 25,
    indicators: ["UPI payment context"],
    patterns: [/\bupi\b/i, /\bcollect request\b/i, /\bpayment request\b/i, /\bpaytm|phonepe|gpay|google pay\b/i],
  },
  {
    intent: "Payment Fraud",
    scamType: "Payment Fraud",
    weight: 24,
    indicators: ["Financial request"],
    patterns: [/\btransfer.{0,20}(money|amount|funds)\b/i, /\bprocessing fee\b/i, /\badvance payment\b/i, /\bpay.{0,20}(claim|release|unlock)\b/i],
  },
  {
    intent: "Lottery/Prize Scam",
    scamType: "Lottery / Prize Scam",
    weight: 22,
    indicators: ["Prize claim"],
    patterns: [/\b(won|winner|lottery|lucky draw|jackpot|prize|reward|selected)\b/i],
  },
  {
    intent: "Delivery/Courier Scam",
    scamType: "Delivery / Courier Scam",
    weight: 20,
    indicators: ["Courier impersonation"],
    patterns: [/\b(courier|parcel|delivery|customs|shipment|package held)\b/i],
  },
  {
    intent: "Remote Access Scam",
    scamType: "Remote Access Scam",
    weight: 30,
    indicators: ["Remote access request"],
    patterns: [/\b(anydesk|teamviewer|remote access|screen share|screen sharing|install this app)\b/i],
  },
  {
    intent: "Government Impersonation",
    scamType: "Government Impersonation",
    weight: 24,
    indicators: ["Authority impersonation"],
    patterns: [/\b(income tax|police|court|arrest warrant|legal action|aadhaar|cybercrime|customs)\b/i],
  },
  {
    intent: "Job Scam",
    scamType: "Job Scam",
    weight: 18,
    indicators: ["Job offer context"],
    patterns: [/\bjob offer|work from home|registration fee|interview fee|easy income|daily earning\b/i],
  },
  {
    intent: "Investment Scam",
    scamType: "Investment Scam",
    weight: 20,
    indicators: ["Unrealistic investment return"],
    patterns: [/\binvestment|guaranteed returns|double your money|crypto profit|trading profit\b/i],
  },
  {
    intent: "Fake Customer Support",
    scamType: "Fake Customer Support",
    weight: 18,
    indicators: ["Support impersonation"],
    patterns: [/\bcustomer support|helpline|refund support|support executive\b/i],
  },
  {
    intent: "Romance Scam",
    scamType: "Romance Scam",
    weight: 18,
    indicators: ["Relationship manipulation"],
    patterns: [/\bmy love|trust me|send money|emergency help|gift card\b/i],
  },
  {
    intent: "Malware Distribution",
    scamType: "Malware Distribution",
    weight: 24,
    indicators: ["Suspicious install request"],
    patterns: [/\bdownload apk|install app|security app|update app|malware|virus removal\b/i],
  },
  {
    intent: "Social Engineering",
    scamType: "Social Engineering",
    weight: 16,
    indicators: ["Urgency or pressure"],
    patterns: [/\burgent|immediately|last chance|within 24 hours|account will be blocked|act now|threat\b/i],
  },
];

function detectIntent(text = "", entities = {}) {
  const source = String(text || "");
  const matches = INTENTS.filter((intent) => intent.patterns.some((pattern) => pattern.test(source)));

  if (entities.upiIds?.length) {
    const upiIntent = INTENTS.find((item) => item.intent === "UPI Fraud");
    if (upiIntent && !matches.includes(upiIntent)) matches.push(upiIntent);
  }

  if (entities.otpReferences?.length) {
    const otpIntent = INTENTS.find((item) => item.intent === "OTP Theft");
    if (otpIntent && !matches.includes(otpIntent)) matches.push(otpIntent);
  }

  const primary = matches.sort((a, b) => b.weight - a.weight)[0];

  return {
    scamType: primary?.scamType || "Unknown / Other",
    attackerIntent: primary?.intent || "Other",
    intentScore: Math.min(40, matches.reduce((sum, item) => sum + Math.ceil(item.weight / 3), 0)),
    indicators: [...new Set(matches.flatMap((item) => item.indicators))],
    matchedIntents: matches.map((item) => item.intent),
  };
}

module.exports = { detectIntent };
