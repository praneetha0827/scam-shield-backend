// Lightweight rule-based scam analyzer.
// Each matched rule adds weighted points and a human-readable reason.
// Later this can be swapped for a real ML/LLM call without changing the API contract.

const RULES = [
  {
    reason: "Fake prize / lottery / lucky draw claim",
    weight: 30,
    test: (t) => /\b(won|winner|lucky draw|lottery|prize|jackpot|selected)\b/i.test(t),
  },
  {
    reason: "Urgent call to action / time pressure",
    weight: 15,
    test: (t) => /\b(urgent|immediately|act now|expire|within 24 hours|last chance|hurry)\b/i.test(t),
  },
  {
    reason: "Suspicious shortened URL",
    weight: 20,
    test: (t) => /\b(bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd|rb\.gy)\/\S+/i.test(t),
  },
  {
    reason: "Requests personal or financial information",
    weight: 20,
    test: (t) => /\b(otp|pin|cvv|account number|password|aadhaar|card number|bank details)\b/i.test(t),
  },
  {
    reason: "Impersonates a bank, government, or courier service",
    weight: 15,
    test: (t) => /\b(income tax|rbi|kyc|customs|courier|parcel held|electricity board|bank account (blocked|suspended))\b/i.test(t),
  },
  {
    reason: "Asks to click a link to claim/verify/unlock",
    weight: 15,
    test: (t) => /\b(click here|click the link|verify now|claim now|unlock)\b/i.test(t),
  },
  {
    reason: "Unusual sender pattern (all caps, excessive punctuation)",
    weight: 8,
    test: (t) => /(!!!|[A-Z]{6,})/.test(t),
  },
  {
    reason: "Requests money transfer or advance payment",
    weight: 20,
    test: (t) => /\b(processing fee|advance payment|transfer.{0,15}(amount|money)|pay.{0,15}to (claim|unlock|release))\b/i.test(t),
  },
];

function analyzeText(text) {
  const matched = RULES.filter((r) => r.test(text));
  let score = matched.reduce((sum, r) => sum + r.weight, 0);
  score = Math.min(100, score);

  // A completely clean message with no red flags gets a deterministic baseline.
  if (matched.length === 0) score = 5;

  const verdict = score >= 70 ? "Dangerous" : score >= 40 ? "Suspicious" : "Safe";

  return {
    score,
    verdict,
    reasons: matched.map((r) => r.reason),
  };
}

// Common brand names scammers impersonate via lookalike domains
const IMPERSONATED_BRANDS = ["paypal", "amazon", "microsoft", "apple", "netflix", "google", "bankofamerica", "hdfc", "icici", "sbi"];
const FREEMAIL_DOMAINS = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "rediffmail.com"];

const EMAIL_RULES = [
  {
    reason: "Sender domain looks like a lookalike/spoofed brand domain",
    weight: 25,
    test: (senderEmail) => {
      if (!senderEmail || !senderEmail.includes("@")) return false;
      const domain = senderEmail.split("@")[1]?.toLowerCase() || "";
      return IMPERSONATED_BRANDS.some((brand) => domain.includes(brand) && !domain.endsWith(`${brand}.com`));
    },
  },
  {
    reason: "Claims to be an official company but sent from a free email provider",
    weight: 20,
    test: (senderEmail, subject, body) => {
      if (!senderEmail || !senderEmail.includes("@")) return false;
      const domain = senderEmail.split("@")[1]?.toLowerCase() || "";
      const text = `${subject} ${body}`.toLowerCase();
      const mentionsBrand = IMPERSONATED_BRANDS.some((b) => text.includes(b));
      return FREEMAIL_DOMAINS.includes(domain) && mentionsBrand;
    },
  },
  {
    reason: "Uses a generic greeting instead of your name",
    weight: 8,
    test: (senderEmail, subject, body) => /\b(dear customer|dear user|dear valued customer|dear account holder)\b/i.test(body || ""),
  },
];

function analyzeEmail({ senderEmail = "", subject = "", body = "" }) {
  const combinedText = `${subject} ${body}`;
  const base = analyzeText(combinedText);

  const emailMatched = EMAIL_RULES.filter((r) => r.test(senderEmail, subject, body));
  const extraScore = emailMatched.reduce((sum, r) => sum + r.weight, 0);

  const score = Math.min(100, base.score + extraScore);
  const reasons = [...base.reasons, ...emailMatched.map((r) => r.reason)];
  const verdict = score >= 70 ? "Dangerous" : score >= 40 ? "Suspicious" : "Safe";

  return { score, verdict, reasons };
}

// ---- Module 6: Website Analysis ----
const SUSPICIOUS_TLDS = ["xyz", "top", "club", "info", "online", "click", "site", "work", "loan", "gq", "tk", "ml"];
const SUSPICIOUS_URL_KEYWORDS = ["free", "gift", "claim", "verify", "login-secure", "secure-update", "prize", "reward", "unlock", "confirm-account"];

function analyzeWebsite(rawUrl) {
  const reasons = [];
  let score = 0;
  let url;

  try {
    url = new URL(rawUrl.match(/^https?:\/\//i) ? rawUrl : `http://${rawUrl}`);
  } catch {
    return { score: 50, verdict: "Suspicious", reasons: ["Could not parse this as a valid URL"] };
  }

  const hostname = url.hostname.toLowerCase();
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);

  if (url.protocol !== "https:") {
    reasons.push("Site does not use HTTPS (no valid SSL encryption)");
    score += 20;
  }

  if (isIp) {
    reasons.push("URL uses a raw IP address instead of a domain name");
    score += 25;
  }

  const tld = hostname.split(".").pop();
  if (SUSPICIOUS_TLDS.includes(tld)) {
    reasons.push(`Uses a domain extension (.${tld}) commonly abused for scam sites`);
    score += 15;
  }

  const subdomainCount = hostname.split(".").length - 2;
  if (subdomainCount >= 2) {
    reasons.push("Unusually large number of subdomains");
    score += 10;
  }

  if ((hostname.match(/-/g) || []).length >= 2) {
    reasons.push("Domain contains multiple hyphens, a common phishing pattern");
    score += 10;
  }

  const lowerFullUrl = rawUrl.toLowerCase();
  if (SUSPICIOUS_URL_KEYWORDS.some((k) => lowerFullUrl.includes(k))) {
    reasons.push("URL contains scam-associated keywords (free/claim/verify/prize/etc.)");
    score += 15;
  }

  const brandMatch = IMPERSONATED_BRANDS.find((brand) => hostname.includes(brand) && !hostname.endsWith(`${brand}.com`));
  if (brandMatch) {
    reasons.push(`Domain appears to impersonate "${brandMatch}" without being the official domain`);
    score += 25;
  }

  if (/bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd|rb\.gy/i.test(hostname)) {
    reasons.push("This is a shortened URL - the real destination is hidden");
    score += 15;
  }

  score = Math.min(100, score);
  const verdict = score >= 70 ? "Dangerous" : score >= 40 ? "Suspicious" : "Safe";

  return { score, verdict, reasons };
}

module.exports = { analyzeText, analyzeEmail, analyzeWebsite, analyzeVoice };

// ---- Module 8: Voice Analysis ----
const VOICE_RULES = [
  {
    reason: "Impersonates government, police, or tax authority over the phone",
    weight: 25,
    test: (t) => /\b(income tax department|police department|arrest warrant|legal action|court notice|customs department|cybercrime cell)\b/i.test(t),
  },
  {
    reason: "Robocall / automated IVR pattern (press a number to continue)",
    weight: 15,
    test: (t) => /\bpress\s*(1|one|2|two)\b/i.test(t),
  },
  {
    reason: "Asks the caller to install remote access / screen-sharing software",
    weight: 25,
    test: (t) => /\b(anydesk|teamviewer|remote access|screen share|screen sharing|install this app)\b/i.test(t),
  },
  {
    reason: "Demands payment via gift cards, crypto, or wire transfer",
    weight: 25,
    test: (t) => /\b(gift card|google play card|itunes card|bitcoin|crypto|wire transfer|western union)\b/i.test(t),
  },
  {
    reason: "Claims a family member is in trouble and needs urgent money (impersonation scam)",
    weight: 25,
    test: (t) => /\b(your (son|daughter|grandson|granddaughter|child) (is|has been) (in|arrested|kidnapped|in an accident))\b/i.test(t),
  },
  {
    reason: "Threatens account suspension or legal consequences unless caller acts now",
    weight: 15,
    test: (t) => /\b(account (will be|is) (suspended|blocked|frozen)|failure to comply|immediate action required)\b/i.test(t),
  },
];

function analyzeVoice({ callerNumber = "", transcript = "" }) {
  const base = analyzeText(transcript);

  const voiceMatched = VOICE_RULES.filter((r) => r.test(transcript));
  const extraScore = voiceMatched.reduce((sum, r) => sum + r.weight, 0);

  let score = Math.min(100, base.score + extraScore);
  const reasons = [...base.reasons, ...voiceMatched.map((r) => r.reason)];

  if (callerNumber && /^(\+?1)?800|unknown|private|blocked/i.test(callerNumber.replace(/\s/g, ""))) {
    reasons.push("Caller ID is hidden, spoofed, or from a suspicious range");
    score = Math.min(100, score + 10);
  }

  const verdict = score >= 70 ? "Dangerous" : score >= 40 ? "Suspicious" : "Safe";

  return { score, verdict, reasons };
}
