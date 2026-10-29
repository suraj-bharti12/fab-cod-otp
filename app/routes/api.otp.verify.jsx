// app/routes/api.otp.verify.jsx   ->   POST /api/otp/verify
import { authenticate } from "../shopify.server";
import {
  normalizeIndianPhone,
  takeVerifyAttempt,
  clearVerifyAttempts,
  verifyOtp,
  signAttribute,
  maskPhoneForLog,
} from "../otp.server";

export const loader = async ({ request }) => {
  const { cors } = await authenticate.public.checkout(request);
  return cors(Response.json({ ok: false, error: "Use POST" }, { status: 405 }));
};

export const action = async ({ request }) => {
  const { cors } = await authenticate.public.checkout(request);
  const reply = (body, status = 200) => cors(Response.json(body, { status }));

  const body = await request.json().catch(() => ({}));
  const phone = normalizeIndianPhone(body.phone);
  const otp = String(body.otp || "").trim();
  if (!phone || !/^\d{4,8}$/.test(otp)) {
    return reply({ ok: false, error: "Invalid OTP." }, 400);
  }

  if (!takeVerifyAttempt(phone)) {
    return reply({ ok: false, error: "Too many incorrect attempts. Please request a new OTP." }, 429);
  }

  try {
    const r = await verifyOtp(phone, otp);
    console.log(`[otp/verify] ${maskPhoneForLog(phone)} -> ${r.status}`);
    if (!r.ok) return reply({ ok: false, error: "Incorrect or expired OTP." }, 400);

    clearVerifyAttempts(phone);
    const verifiedAt = new Date().toISOString();
    return reply({ ok: true, verifiedAt, token: signAttribute(phone, verifiedAt) });
  } catch (e) {
    console.error(`[otp/verify] ${maskPhoneForLog(phone)} -> request failed: ${e?.message || "unknown"}`);
    return reply({ ok: false, error: "OTP service unavailable." }, 502);
  }
};