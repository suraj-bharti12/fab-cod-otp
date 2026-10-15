// app/routes/api.otp.send.jsx   ->   POST /api/otp/send
import { authenticate } from "../shopify.server";
import {
  normalizeIndianPhone,
  checkSendLimit,
  recordSend,
  sendOtp,
} from "../otp.server";

// Also handles OPTIONS (CORS preflight) and GET
export const loader = async ({ request }) => {
  const { cors } = await authenticate.public.checkout(request);
  return cors(Response.json({ ok: false, error: "Use POST" }, { status: 405 }));
};

export const action = async ({ request }) => {
  // Verifies the checkout extension session token (throws 401 if invalid)
  const { sessionToken, cors } = await authenticate.public.checkout(request);
  const reply = (body, status = 200) => cors(Response.json(body, { status }));

  const { phone: rawPhone } = await request.json().catch(() => ({}));
  const phone = normalizeIndianPhone(rawPhone);
  if (!phone) return reply({ ok: false, error: "Invalid mobile number." }, 400);

  const limit = checkSendLimit(phone);
  if (!limit.ok) {
    return reply(
      {
        ok: false,
        retryAfter: limit.retryAfter,
        error: `Please try again in ${limit.retryAfter}s.`,
      },
      429,
    );
  }

  try {
    const r = await sendOtp(phone);
    console.log(`[otp/send] ${sessionToken.dest} ${phone} -> ${r.raw}`);
    if (!r.ok) {
      return reply({ ok: false, error: "Could not send OTP. Please try again." }, 502);
    }
    recordSend(phone);
    return reply({ ok: true });
  } catch (e) {
    console.error("[otp/send] error", e);
    return reply({ ok: false, error: "OTP service unavailable." }, 502);
  }
};