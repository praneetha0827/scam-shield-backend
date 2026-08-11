const assert = require("assert");
const {
  analyzeText,
  analyzeEmail,
  analyzeWebsite,
  analyzeVoice,
  analyzeUpiTransaction,
  analyzeCallerImpersonation,
} = require("../utils/scamAnalyzer");
const { analyzeRisk } = require("../utils/riskEngine");

const severity = { Safe: 0, Suspicious: 1, Dangerous: 2 };
const riskSeverity = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

const cases = [
  {
    name: "Legitimate bank notification",
    run: () => analyzeText("Your SBI account ending 1234 was debited by Rs 540 at grocery store. If this was not you, contact official support."),
    expectMaxVerdict: "Suspicious",
  },
  {
    name: "Fake bank OTP phishing",
    run: () => analyzeText("Urgent: Your bank account will be blocked. Verify now and share OTP at http://bit.ly/bankkyc"),
    expectMinRisk: "HIGH",
    expectIntent: "OTP Theft",
  },
  {
    name: "Fake delivery scam",
    run: () => analyzeText("Your parcel is held by customs. Pay processing fee to release delivery within 24 hours."),
    expectMinRisk: "HIGH",
  },
  {
    name: "Job scam",
    run: () => analyzeRisk({ text: "Work from home job offer. Pay registration fee today to start earning daily income.", sourceType: "Interceptor" }),
    expectMinRisk: "HIGH",
    expectIntent: "Job Scam",
  },
  {
    name: "Fake customer support",
    run: () => analyzeCallerImpersonation({ callerNumber: "Unknown", claimedOrganization: "Customer support", context: "Install AnyDesk so we can refund your money.", unknownCaller: true }),
    expectMinRisk: "CRITICAL",
    expectIntent: "Remote Access Scam",
  },
  {
    name: "OTP request",
    run: () => analyzeText("Your verification code is 839201. Share this OTP with our support executive immediately."),
    expectMinRisk: "HIGH",
    expectIntent: "OTP Theft",
  },
  {
    name: "UPI payment scam",
    run: () => analyzeUpiTransaction({ upiId: "unknown@upi", recipient: "new seller", amount: "25000", context: "Pay advance payment to claim prize", firstTimeRecipient: true }),
    expectMinRisk: "CRITICAL",
    expectIntent: "UPI Fraud",
  },
  {
    name: "Suspicious URL",
    run: () => analyzeWebsite("http://paypal-secure-login-verify.xyz/claim"),
    expectMinRisk: "HIGH",
  },
  {
    name: "Known scam-style caller",
    run: () => analyzeCallerImpersonation({ callerNumber: "Unknown", claimedOrganization: "SBI Bank", context: "Your account is suspended. Share OTP and transfer money by UPI.", unknownCaller: true }),
    expectMinRisk: "CRITICAL",
  },
  {
    name: "Legitimate caller",
    run: () => analyzeCallerImpersonation({ callerNumber: "+91 98765 43210", claimedOrganization: "Clinic reception", context: "This is a reminder for your appointment tomorrow.", unknownCaller: false }),
    expectMaxVerdict: "Suspicious",
  },
  {
    name: "Scam screenshot OCR text",
    run: () => analyzeRisk({ text: "Screenshot OCR text: Congrats winner. Claim Rs 25000 now at http://bit.ly/reward", sourceType: "Interceptor" }),
    expectMinRisk: "HIGH",
  },
  {
    name: "Legitimate screenshot OCR text",
    run: () => analyzeRisk({ text: "Screenshot OCR text: Meeting moved to 3 PM. Please review the agenda before joining.", sourceType: "Interceptor" }),
    expectMaxVerdict: "Suspicious",
  },
  {
    name: "False positive friendly message",
    run: () => analyzeText("Lunch at 1 pm? I will bring the notes from class."),
    expectVerdict: "Safe",
  },
  {
    name: "Empty input",
    run: () => analyzeText(""),
    expectVerdict: "Safe",
  },
  {
    name: "Email phishing",
    run: () => analyzeEmail({ senderEmail: "security@paypa1-verify.com", subject: "Urgent verify account", body: "Dear customer, verify your password and OTP now." }),
    expectMinRisk: "HIGH",
    expectIntent: "OTP Theft",
  },
  {
    name: "Voice remote access scam",
    run: () => analyzeVoice({ callerNumber: "Unknown", transcript: "This is bank support. Install AnyDesk and share your screen to unblock account immediately." }),
    expectMinRisk: "CRITICAL",
    expectIntent: "Remote Access Scam",
  },
];

function check(testCase) {
  const result = testCase.run();

  if (testCase.expectVerdict) {
    assert.strictEqual(result.verdict, testCase.expectVerdict, `${testCase.name}: expected verdict ${testCase.expectVerdict}, got ${result.verdict}`);
  }

  if (testCase.expectMaxVerdict) {
    assert(
      severity[result.verdict] <= severity[testCase.expectMaxVerdict],
      `${testCase.name}: expected verdict <= ${testCase.expectMaxVerdict}, got ${result.verdict}`
    );
  }

  if (testCase.expectMinRisk) {
    assert(
      riskSeverity[result.riskLevel] >= riskSeverity[testCase.expectMinRisk],
      `${testCase.name}: expected risk >= ${testCase.expectMinRisk}, got ${result.riskLevel} (${result.score})`
    );
  }

  if (testCase.expectIntent) {
    assert(
      result.attackerIntent === testCase.expectIntent || result.matchedIntents?.includes(testCase.expectIntent),
      `${testCase.name}: expected intent ${testCase.expectIntent}, got ${result.attackerIntent}`
    );
  }

  assert(Number.isFinite(result.score), `${testCase.name}: score must be numeric`);
  assert(result.score >= 0 && result.score <= 100, `${testCase.name}: score out of range`);
  assert(result.riskLevel, `${testCase.name}: riskLevel missing`);
  assert(Array.isArray(result.reasons), `${testCase.name}: reasons must be an array`);

  return result;
}

let passed = 0;

for (const testCase of cases) {
  const result = check(testCase);
  passed += 1;
  console.log(`PASS ${testCase.name}: ${result.riskLevel}/${result.verdict} score=${result.score} intent=${result.attackerIntent}`);
}

console.log(`\n${passed}/${cases.length} risk regression cases passed.`);
