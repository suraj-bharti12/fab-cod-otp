// app/routes/webhooks.compliance.jsx   ->   POST /webhooks/compliance
// Mandatory GDPR compliance webhooks: customers/data_request, customers/redact, shop/redact
import { authenticate } from "../shopify.server";
import db from "../db.server";

export const action = async ({ request }) => {
  // Verifies the Shopify HMAC signature (throws 401 if invalid)
  const { topic, shop } = await authenticate.webhook(request);
  const t = String(topic).toUpperCase().replace("/", "_");
  console.log(`[compliance] ${t} for ${shop}`);

  switch (t) {
    case "CUSTOMERS_DATA_REQUEST":
      // This app does not store customer data (OTP rate-limit data is in memory only
      // and expires within an hour). The verification result lives on the Shopify order
      // itself as order attributes, so there is nothing extra to export.
      break;
    case "CUSTOMERS_REDACT":
      // No customer data stored by this app, nothing to delete.
      break;
    case "SHOP_REDACT":
      // Shop uninstalled 48h ago: delete any remaining sessions for this shop.
      await db.session.deleteMany({ where: { shop } });
      break;
    default:
      break;
  }

  return new Response(null, { status: 200 });
};