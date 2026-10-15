import '@shopify/ui-extensions/preact';
import {render} from 'preact';
import {useEffect, useState} from 'preact/hooks';
import {
  useBuyerJourneyIntercept,
  useExtensionCapability,
} from '@shopify/ui-extensions/checkout/preact';

// ---- Order attributes (key -> value) saved on the order ----
const ATTR = {
  VERIFIED: 'cod_otp_verified', // "true" / "false"
  PHONE: 'cod_otp_phone', // 91XXXXXXXXXX
  VERIFIED_AT: 'cod_otp_verified_at', // ISO time
  TOKEN: 'cod_otp_token', // HMAC signature from backend (tamper check)
};

const DEFAULT_COD_TYPES = 'paymentOnDelivery,manualPayment';
const RESEND_SECONDS = 30;
const OTP_LENGTH = 4; // Number of digits in the OTP

export default function extension() {
  render(<Extension />, document.body);
}

/** "+91 98765-43210" / "098765 43210" / "9876543210" -> "919876543210" */
function normalizeIndianPhone(raw) {
  let d = String(raw || '').replace(/\D/g, '');
  if (d.length === 11 && d.startsWith('0')) d = d.slice(1);
  if (d.length === 10) d = '91' + d;
  return /^91[6-9]\d{9}$/.test(d) ? d : null;
}

function maskPhone(p) {
  return p ? `+91 ${p.slice(2, 4)}XXXXX${p.slice(-3)}` : '';
}

function formatPhone(p) {
  return p ? `+91 ${p.slice(2, 7)} ${p.slice(7)}` : '';
}

function Extension() {
  // ---------- Checkout data (signals => auto re-render) ----------
  const settings = shopify.settings.value || {};
  const backendUrl = String(settings.backend_url || '').trim().replace(/\/+$/, '');
  const codTypes = String(settings.cod_payment_types || DEFAULT_COD_TYPES)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  const selectedPayments = shopify.selectedPaymentOptions.value || [];
  const isCod = selectedPayments.some((o) => codTypes.includes(o.type));

  const shippingPhone = shopify.shippingAddress?.value?.phone || '';
  const attributes = shopify.attributes.value || [];
  const getAttr = (k) => attributes.find((a) => a.key === k)?.value;
  const canUpdateAttributes =
    shopify.instructions.value?.attributes?.canUpdateAttributes !== false;
  const blockProgressGranted = useExtensionCapability('block_progress');

  // ---------- Local UI state ----------
  const [otp, setOtp] = useState('');
  const [otpSentTo, setOtpSentTo] = useState(null);
  const [loading, setLoading] = useState(null); // 'send' | 'verify' | null
  const [error, setError] = useState('');
  const [info, setInfo] = useState('');
  const [cooldown, setCooldown] = useState(0);

  // Resend countdown
  useEffect(() => {
    if (cooldown <= 0) return undefined;
    const t = setTimeout(() => setCooldown((c) => c - 1), 1000);
    return () => clearTimeout(t);
  }, [cooldown]);

  // Phone always comes from the shipping address (not editable here)
  const phone = normalizeIndianPhone(shippingPhone);
  const isVerified =
    getAttr(ATTR.VERIFIED) === 'true' && !!phone && getAttr(ATTR.PHONE) === phone;

  // If the number changes, clear the old "verified" attribute
  useEffect(() => {
    if (!canUpdateAttributes) return;
    const storedPhone = getAttr(ATTR.PHONE);
    if (getAttr(ATTR.VERIFIED) === 'true' && storedPhone && storedPhone !== phone) {
      setAttributes({[ATTR.VERIFIED]: 'false', [ATTR.TOKEN]: ''}).catch(() => {});
    }
    if (otpSentTo && otpSentTo !== phone) {
      setOtpSentTo(null);
      setOtp('');
    }
  }, [phone]);

  // ---------- Block "Complete order" until OTP verified (only for COD) ----------
  useBuyerJourneyIntercept(({canBlockProgress}) => {
    if (!canBlockProgress || !isCod || isVerified || !canUpdateAttributes) {
      return {behavior: 'allow'};
    }
    return {
      behavior: 'block',
      reason: 'COD OTP not verified',
      errors: [
        {message: 'Please verify your mobile number via OTP to use Cash on Delivery.'},
      ],
      perform: (result) => {
        if (result.behavior === 'block') {
          setError('Please verify the OTP before placing your order.');
        }
      },
    };
  });

  // ---------- Helpers ----------
  async function setAttributes(map) {
    for (const [key, value] of Object.entries(map)) {
      const res = await shopify.applyAttributeChange({type: 'updateAttribute', key, value});
      if (res.type === 'error') throw new Error(res.message || 'Could not save attribute');
    }
  }

  async function callBackend(path, body) {
    if (!backendUrl) throw new Error('OTP service is not configured (backend URL missing).');
    const token = await shopify.sessionToken.get();
    const res = await fetch(`${backendUrl}/api${path}`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json', Authorization: `Bearer ${token}`},
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.ok) {
      if (data.retryAfter) setCooldown(data.retryAfter);
      throw new Error(data.error || 'Something went wrong. Please try again.');
    }
    return data;
  }

  async function sendOtp() {
    setError('');
    setInfo('');
    if (!phone) {
      setError('Please add a valid 10-digit mobile number in your delivery address.');
      return;
    }
    setLoading('send');
    try {
      await callBackend('/otp/send', {phone});
      setOtpSentTo(phone);
      setOtp('');
      setCooldown(RESEND_SECONDS);
      setInfo(`OTP has been sent to ${maskPhone(phone)}.`);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(null);
    }
  }

  async function verifyOtp() {
    setError('');
    setInfo('');
    const code = otp.trim();
    if (code.length !== OTP_LENGTH) {
      setError(`Please enter the ${OTP_LENGTH}-digit OTP you received via SMS.`);
      return;
    }
    setLoading('verify');
    try {
      const data = await callBackend('/otp/verify', {phone, otp: code});
      await setAttributes({
        [ATTR.VERIFIED]: 'true',
        [ATTR.PHONE]: phone,
        [ATTR.VERIFIED_AT]: data.verifiedAt,
        [ATTR.TOKEN]: data.token,
      });
      setOtp('');
      setOtpSentTo(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(null);
    }
  }

  // ---------- UI ----------
  const editorType = shopify.extension.editor?.type;

  if (editorType === 'checkout' && !blockProgressGranted) {
    return (
      <s-banner tone="warning" heading="COD OTP: checkout blocking is off">
        In the checkout editor, select this app block and enable "Allow app to block
        checkout". Otherwise COD orders can be placed without OTP verification.
      </s-banner>
    );
  }

  if (!isCod) return null;

  if (!canUpdateAttributes) {
    return (
      <s-banner tone="warning">
        OTP verification is not available for this checkout.
      </s-banner>
    );
  }

  if (isVerified) {
    return (
      <s-banner tone="success" heading="Mobile number verified">
        {maskPhone(phone)} — you can now place your order with Cash on Delivery.
      </s-banner>
    );
  }

  const otpSent = otpSentTo === phone;

  return (
    <s-section heading="Verify OTP for Cash on Delivery">
      <s-stack gap="base">
        <s-text color="subdued">
          To confirm your COD order, we will send an OTP to your mobile number.
        </s-text>

        {phone ? (
          <s-stack gap="base">
            <s-text>
              Mobile number: <s-text type="strong">{formatPhone(phone)}</s-text>
            </s-text>
            <s-text color="subdued">
              To use a different number, update the phone number in your delivery address.
            </s-text>
          </s-stack>
        ) : (
          <s-banner tone="critical">
            Please add a valid 10-digit mobile number in your delivery address to use
            Cash on Delivery.
          </s-banner>
        )}

        {!phone ? null : otpSent ? (
          <s-stack gap="base">
            <s-text-field
              label={`Enter ${OTP_LENGTH}-digit OTP`}
              value={otp}
              maxLength={OTP_LENGTH}
              autocomplete="one-time-code"
              disabled={loading !== null}
              onInput={(e) => {
                const raw = e.currentTarget.value || '';
                // Digits only, max OTP_LENGTH characters
                const clean = raw.replace(/\D/g, '').slice(0, OTP_LENGTH);
                if (clean !== raw) e.currentTarget.value = clean;
                setOtp(clean);
              }}
            />
            <s-stack direction="inline" gap="base">
              <s-button
                variant="primary"
                loading={loading === 'verify'}
                disabled={loading !== null || otp.length !== OTP_LENGTH}
                onClick={verifyOtp}
              >
                Verify OTP
              </s-button>
              <s-button
                variant="secondary"
                loading={loading === 'send'}
                disabled={loading !== null || cooldown > 0}
                onClick={sendOtp}
              >
                {cooldown > 0 ? `Resend in ${cooldown}s` : 'Resend OTP'}
              </s-button>
            </s-stack>
          </s-stack>
        ) : (
          <s-button
            variant="primary"
            loading={loading === 'send'}
            disabled={loading !== null || cooldown > 0}
            onClick={sendOtp}
          >
            {cooldown > 0 ? `Send OTP (${cooldown}s)` : 'Send OTP'}
          </s-button>
        )}

        {info ? <s-banner tone="info">{info}</s-banner> : null}
        {error ? <s-banner tone="critical">{error}</s-banner> : null}
      </s-stack>
    </s-section>
  );
}