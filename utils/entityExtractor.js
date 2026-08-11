const URL_REGEX = /\bhttps?:\/\/[^\s<>"']+|\b(?:www\.)?[a-z0-9.-]+\.[a-z]{2,}(?:\/[^\s<>"']*)?/gi;
const EMAIL_REGEX = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const PHONE_REGEX = /(?:\+?\d[\s-]?){8,15}\d/g;
const UPI_REGEX = /\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z][a-zA-Z0-9.\-_]{2,64}\b/g;
const AMOUNT_REGEX = /(?:₹|rs\.?|inr)\s?[\d,]+(?:\.\d{1,2})?|\b[\d,]+(?:\.\d{1,2})?\s?(?:rupees|inr)\b/gi;
const OTP_REGEX = /\b(?:otp|one[-\s]?time password|verification code|code)\b.{0,30}\b\d{4,8}\b|\b\d{4,8}\b.{0,30}\b(?:otp|one[-\s]?time password|verification code|code)\b/gi;

const unique = (items) => [...new Set(items.map((item) => String(item).trim()).filter(Boolean))];

function extractEntities(text = "") {
  const source = String(text || "");
  const emails = unique(source.match(EMAIL_REGEX) || []);
  const upiIds = unique(source.match(UPI_REGEX) || []).filter((upi) => !emails.includes(upi));

  return {
    urls: unique(source.match(URL_REGEX) || []),
    emails,
    phoneNumbers: unique(source.match(PHONE_REGEX) || []),
    upiIds,
    amounts: unique(source.match(AMOUNT_REGEX) || []),
    otpReferences: unique(source.match(OTP_REGEX) || []),
  };
}

module.exports = { extractEntities };
