// app/otp.server.js
// Gupshup OTP helper + rate limiting. Ye file sirf server par chalti hai,
// isliye Gupshup ka password yahan safe hai (buyer ko nahi dikhta).
// NOTE: Is app ka code public GitHub repo me push na karein.
import crypto from "node:crypto";

// ======================= CONFIG — yahan apni values daalein =======================
const GUPSHUP_USERID = "2000137285";
const GUPSHUP_PASSWORD = "hYODZWsF0";
const GUPSHUP_API_URL = "https://enterprise.smsgupshup.com/GatewayAPI/rest";

// DLT-approved template se EXACT match hona chahiye (ek-ek word, space, full stop).
// Template me jahan {#var#} hai, wahan %code% likhein.
const OTP_MESSAGE = "Dear Customer, Your OTP is %code%. Please use this for any of your interactions on Fabindia website. OTP is valid for 30 secs.";
const OTP_CODE_LENGTH = "4";

// ---- DLT details (Gupshup dashboard / DLT portal se) ----
// Khaali ("") chhodne par ye parameter Gupshup ko nahi bheja jayega.
const SENDER_MASK = "";          // 6-letter Sender ID / Header, e.g. "FABIND"
const DLT_TEMPLATE_ID = "";      // DLT Template ID (numeric), e.g. "1107160000000000000"
const PRINCIPAL_ENTITY_ID = "";  // DLT Entity ID (numeric), e.g. "1101160000000000000"

// cod_otp_token signature ke liye secret (koi bhi lambi random string)
const SIGNING_SECRET = "dce436042a8a54ce5583d0497295733dd5b902448f05b04c9e730c1b962bc1dc";
// ===================================================================================

// ---------------------------------------------------------------------------
// Phone
// ---------------------------------------------------------------------------
/** "+91 98765-43210" / "098765 43210" / "9876543210" -> "919876543210" */
export function normalizeIndianPhone(raw) {
  let d = String(raw || "").replace(/\D/g, "");
  if (d.length === 11 && d.startsWith("0")) d = d.slice(1);
  if (d.length === 10) d = "91" + d;
  return /^91[6-9]\d{9}$/.test(d) ? d : null;
}

// ---------------------------------------------------------------------------
// Rate limits (in-memory; ek server instance ke liye theek hai)
// ---------------------------------------------------------------------------
const RESEND_COOLDOWN_MS = 30_000; // 30 sec between OTPs
const MAX_SENDS_PER_HOUR = 5; // per phone number
const MAX_VERIFY_ATTEMPTS = 5; // wrong attempts per OTP
const HOUR = 3_600_000;

const sendLog = new Map(); // phone -> [timestamps]
const verifyAttempts = new Map(); // phone -> count

export function checkSendLimit(phone) {
  const now = Date.now();
  const recent = (sendLog.get(phone) || []).filter((t) => now - t < HOUR);
  sendLog.set(phone, recent);
  const last = recent[recent.length - 1];
  if (last && now - last < RESEND_COOLDOWN_MS) {
    return { ok: false, retryAfter: Math.ceil((RESEND_COOLDOWN_MS - (now - last)) / 1000) };
  }
  if (recent.length >= MAX_SENDS_PER_HOUR) {
    return { ok: false, retryAfter: Math.ceil((HOUR - (now - recent[0])) / 1000) };
  }
  return { ok: true };
}

export function recordSend(phone) {
  const list = sendLog.get(phone) || [];
  list.push(Date.now());
  sendLog.set(phone, list);
  verifyAttempts.set(phone, 0);
}

/** true = attempt allowed (and counted), false = too many attempts */
export function takeVerifyAttempt(phone) {
  const n = verifyAttempts.get(phone) ?? 0;
  if (n >= MAX_VERIFY_ATTEMPTS) return false;
  verifyAttempts.set(phone, n + 1);
  return true;
}

export function clearVerifyAttempts(phone) {
  verifyAttempts.delete(phone);
}

// ---------------------------------------------------------------------------
// Gupshup Enterprise TWO_FACTOR_AUTH
//   Send:   phone_no + msg            -> "success | 91XXXXXXXXXX | <id> | OTP sent"
//   Verify: phone_no + otp_code       -> "success | 91XXXXXXXXXX | <id> | OTP matched"
//   Error:  "error | <code> | <message>"
// ---------------------------------------------------------------------------
async function gupshup2fa(params) {
  const body = new URLSearchParams({
    userid: GUPSHUP_USERID,
    password: GUPSHUP_PASSWORD,
    method: "TWO_FACTOR_AUTH",
    v: "1.1",
    format: "text",
    auth_scheme: "plain",
    ...params,
  });
  const res = await fetch(GUPSHUP_API_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const text = (await res.text()).trim();
  return { ok: res.ok && /^success/i.test(text), raw: text };
}

export function sendOtp(phone) {
  const params = {
    phone_no: phone,
    msg: OTP_MESSAGE,
    otpCodeLength: OTP_CODE_LENGTH,
    otpCodeType: "NUMERIC",
  };
  if (SENDER_MASK) params.mask = SENDER_MASK;
  if (DLT_TEMPLATE_ID) params.dltTemplateId = DLT_TEMPLATE_ID;
  if (PRINCIPAL_ENTITY_ID) params.principalEntityId = PRINCIPAL_ENTITY_ID;
  return gupshup2fa(params);
}

export function verifyOtp(phone, otp) {
  return gupshup2fa({ phone_no: phone, otp_code: otp });
}

// ---------------------------------------------------------------------------
// Signature saved in order attribute "cod_otp_token" so you can prove later
// that verification really came from this server (not set by the buyer).
// ---------------------------------------------------------------------------
export function signAttribute(phone, verifiedAt) {
  return crypto
    .createHmac("sha256", SIGNING_SECRET)
    .update(`${phone}|${verifiedAt}`)
    .digest("hex");
}