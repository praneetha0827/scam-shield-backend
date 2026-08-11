const { analyzeRisk } = require("./riskEngine");

const IMPERSONATED_BRANDS = ["paypal", "amazon", "microsoft", "apple", "netflix", "google", "bankofamerica", "hdfc", "icici", "sbi"];
const FREEMAIL_DOMAINS = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "rediffmail.com"];
const SUSPICIOUS_TLDS = ["xyz", "top", "club", "info", "online", "click", "site", "work", "loan", "gq", "tk", "ml"];
const SUSPICIOUS_URL_KEYWORDS = ["free", "gift", "claim", "verify", "login-secure", "secure-update", "prize", "reward", "unlock", "confirm-account"];
const SUSPICIOUS_ATTACHMENT_EXTENSIONS = ["exe", "apk", "scr", "bat", "cmd", "js", "vbs", "iso", "zip", "rar"];

function emailDomain(email) {
  if (!email || !String(email).includes("@")) return "";
  return String(email).split("@").pop().trim().toLowerCase();
}

function withExtraReasons(result, extraReasons) {
  return {
    ...result,
    reasons: [...new Set([...result.reasons, ...extraReasons])],
    indicators: [...new Set([...result.indicators, ...extraReasons])],
    detectedIndicators: [...new Set([...result.detectedIndicators, ...extraReasons])],
  };
}

function analyzeText(text) {
  return analyzeRisk({ text, sourceType: "Text" });
}

function analyzeEmail({ senderEmail = "", replyTo = "", subject = "", body = "", links = "", headers = "", attachments = "" }) {
  const combinedText = [subject, body, links, headers, attachments].filter(Boolean).join(" ");
  const extraRules = [
    {
      reason: "Sender domain looks like a lookalike/spoofed brand domain",
      indicator: "Lookalike sender domain",
      weight: 25,
      test: () => {
        const domain = emailDomain(senderEmail);
        return IMPERSONATED_BRANDS.some((brand) => domain.includes(brand) && !domain.endsWith(`${brand}.com`));
      },
    },
    {
      reason: "Claims to be an official company but sent from a free email provider",
      indicator: "Brand claim from freemail domain",
      weight: 20,
      test: () => {
        const domain = emailDomain(senderEmail);
        const text = `${subject} ${body}`.toLowerCase();
        const mentionsBrand = IMPERSONATED_BRANDS.some((brand) => text.includes(brand));
        return FREEMAIL_DOMAINS.includes(domain) && mentionsBrand;
      },
    },
    {
      reason: "Uses a generic greeting instead of your name",
      indicator: "Generic greeting",
      weight: 8,
      test: () => /\b(dear customer|dear user|dear valued customer|dear account holder)\b/i.test(body || ""),
    },
    {
      reason: "Reply-To address uses a different domain than the sender",
      indicator: "Reply-To mismatch",
      weight: 18,
      test: () => {
        const senderDomain = emailDomain(senderEmail);
        const replyDomain = emailDomain(replyTo);
        return Boolean(senderDomain && replyDomain && senderDomain !== replyDomain);
      },
    },
    {
      reason: "Email authentication header suggests SPF, DKIM, or DMARC failed",
      indicator: "Email authentication failure",
      weight: 30,
      test: () => /\b(spf|dkim|dmarc)\s*=\s*(fail|softfail|neutral|none)\b/i.test(headers || ""),
    },
    {
      reason: "Email contains a risky attachment type",
      indicator: "Risky attachment",
      weight: 25,
      test: () => {
        const attachmentText = String(attachments || "").toLowerCase();
        return SUSPICIOUS_ATTACHMENT_EXTENSIONS.some((ext) => new RegExp(`\\.${ext}\\b`, "i").test(attachmentText));
      },
    },
  ];

  return analyzeRisk({ text: combinedText, sourceType: "Email", extraRules });
}

function analyzeWebsite(rawUrl) {
  const reasons = [];
  let scoreBoost = 0;
  let parsedUrl;

  try {
    parsedUrl = new URL(rawUrl.match(/^https?:\/\//i) ? rawUrl : `http://${rawUrl}`);
  } catch {
    return withExtraReasons(
      {
        ...analyzeRisk({ text: rawUrl, sourceType: "Website" }),
        score: 50,
        riskScore: 50,
        riskLevel: "HIGH",
        verdict: "Suspicious",
        scamType: "Suspicious Website",
        attackerIntent: "Social Engineering",
        confidence: 0.5,
      },
      ["Could not parse this as a valid URL"]
    );
  }

  const hostname = parsedUrl.hostname.toLowerCase();
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);

  if (parsedUrl.protocol !== "https:") {
    reasons.push("Site does not use HTTPS (no valid SSL encryption)");
    scoreBoost += 20;
  }
  if (isIp) {
    reasons.push("URL uses a raw IP address instead of a domain name");
    scoreBoost += 25;
  }

  const tld = hostname.split(".").pop();
  if (SUSPICIOUS_TLDS.includes(tld)) {
    reasons.push(`Uses a domain extension (.${tld}) commonly abused for scam sites`);
    scoreBoost += 15;
  }
  if (hostname.split(".").length - 2 >= 2) {
    reasons.push("Unusually large number of subdomains");
    scoreBoost += 10;
  }
  if ((hostname.match(/-/g) || []).length >= 2) {
    reasons.push("Domain contains multiple hyphens, a common phishing pattern");
    scoreBoost += 10;
  }
  if (SUSPICIOUS_URL_KEYWORDS.some((keyword) => rawUrl.toLowerCase().includes(keyword))) {
    reasons.push("URL contains scam-associated keywords (free/claim/verify/prize/etc.)");
    scoreBoost += 15;
  }

  const brandMatch = IMPERSONATED_BRANDS.find((brand) => hostname.includes(brand) && !hostname.endsWith(`${brand}.com`));
  if (brandMatch) {
    reasons.push(`Domain appears to impersonate "${brandMatch}" without being the official domain`);
    scoreBoost += 25;
  }
  if (/bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd|rb\.gy/i.test(hostname)) {
    reasons.push("This is a shortened URL - the real destination is hidden");
    scoreBoost += 15;
  }

  const base = analyzeRisk({ text: rawUrl, sourceType: "Website" });
  const score = Math.min(100, Math.max(base.score, scoreBoost + (base.score === 5 ? 0 : base.score)));
  const riskLevel = score >= 75 ? "CRITICAL" : score >= 50 ? "HIGH" : score >= 25 ? "MEDIUM" : "LOW";
  const verdict = riskLevel === "CRITICAL" ? "Dangerous" : riskLevel === "LOW" ? "Safe" : "Suspicious";

  return withExtraReasons(
    {
      ...base,
      score,
      riskScore: score,
      riskLevel,
      verdict,
      scamType: score >= 50 ? "Suspicious Website" : base.scamType,
      confidence: Math.min(0.98, Math.max(base.confidence, score / 100)),
    },
    reasons
  );
}

function analyzeVoice({ callerNumber = "", transcript = "" }) {
  const extraRules = [
    {
      reason: "Impersonates government, police, or tax authority over the phone",
      indicator: "Authority impersonation",
      weight: 25,
      test: () => /\b(income tax department|police department|arrest warrant|legal action|court notice|customs department|cybercrime cell)\b/i.test(transcript),
    },
    {
      reason: "Robocall / automated IVR pattern (press a number to continue)",
      indicator: "Robocall pattern",
      weight: 15,
      test: () => /\bpress\s*(1|one|2|two)\b/i.test(transcript),
    },
    {
      reason: "Caller ID is hidden, spoofed, or from a suspicious range",
      indicator: "Suspicious caller ID",
      weight: 10,
      test: () => Boolean(callerNumber && /^(\+?1)?800|unknown|private|blocked/i.test(callerNumber.replace(/\s/g, ""))),
    },
  ];

  return analyzeRisk({ text: transcript, sourceType: "Voice", extraRules });
}

function analyzeUpiTransaction({ upiId = "", recipient = "", amount = "", context = "", firstTimeRecipient = false } = {}) {
  const text = `${upiId} ${recipient} ${amount} ${context}`;
  const extraRules = [
    {
      reason: "First-time recipient",
      indicator: "First-time recipient",
      weight: 18,
      test: () => Boolean(firstTimeRecipient),
    },
    {
      reason: "Unknown or generic recipient",
      indicator: "Unknown recipient",
      weight: 12,
      test: () => !recipient || /\bunknown|new|not sure|seller|agent\b/i.test(recipient),
    },
    {
      reason: "High-value transaction amount",
      indicator: "High amount",
      weight: 15,
      test: () => {
        const numeric = Number(String(amount).replace(/[^\d.]/g, ""));
        return Number.isFinite(numeric) && numeric >= 10000;
      },
    },
    {
      reason: "UPI ID format is unusual or unverified",
      indicator: "Unverified UPI ID",
      weight: 10,
      test: () => Boolean(upiId && !/^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z][a-zA-Z0-9.\-_]{2,64}$/.test(upiId)),
    },
  ];

  const result = analyzeRisk({ text, sourceType: "UPI", extraRules });

  return {
    ...result,
    scamType: result.scamType === "Unknown / Other" ? "UPI Transaction Risk" : result.scamType,
    recipientRisk: result.riskLevel === "LOW" ? "LOW" : result.riskLevel === "MEDIUM" ? "UNKNOWN" : "HIGH",
    recommendedAction:
      result.recommendedActions.find((action) => action.toLowerCase().includes("send money")) ||
      result.recommendedActions[0] ||
      "Verify the recipient before paying.",
  };
}

function analyzeCallerImpersonation({ callerNumber = "", claimedOrganization = "", context = "", unknownCaller = true } = {}) {
  const text = `${callerNumber} ${claimedOrganization} ${context}`;
  const extraRules = [
    {
      reason: "Unknown caller making a sensitive request",
      indicator: "Unknown caller",
      weight: 14,
      test: () => Boolean(unknownCaller),
    },
    {
      reason: "Caller claims to represent a bank, government, courier, or support team",
      indicator: "Caller impersonation claim",
      weight: 18,
      test: () => /\b(bank|rbi|income tax|police|customs|courier|delivery|support|customer care|kyc)\b/i.test(claimedOrganization || context),
    },
    {
      reason: "Caller asks for OTP, credentials, or payment",
      indicator: "Sensitive request over call",
      weight: 24,
      test: () => /\b(otp|pin|password|cvv|bank details|pay|transfer|upi|remote access|anydesk|teamviewer)\b/i.test(context),
    },
    {
      reason: "Caller uses pressure, threats, or urgent consequences",
      indicator: "Call pressure tactic",
      weight: 16,
      test: () => /\b(urgent|immediately|blocked|suspended|legal action|arrest|last chance|within 24 hours)\b/i.test(context),
    },
  ];

  const result = analyzeRisk({ text, sourceType: "Caller", extraRules });

  return {
    ...result,
    scamType: result.scamType === "Unknown / Other" ? "Caller Impersonation" : result.scamType,
    recommendedAction:
      result.recommendedActions.find((action) => action.toLowerCase().includes("otp")) ||
      "Do not share OTP, PIN, password, banking details, or payment confirmation with the caller.",
  };
}

module.exports = { analyzeText, analyzeEmail, analyzeWebsite, analyzeVoice, analyzeUpiTransaction, analyzeCallerImpersonation };
