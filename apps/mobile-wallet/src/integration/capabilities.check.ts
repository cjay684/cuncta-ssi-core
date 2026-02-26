import { createGatewayClient } from "../core/gateway/client.js";

const baseUrl = process.env.APP_GATEWAY_BASE_URL;
if (!baseUrl) {
  console.log("skip - APP_GATEWAY_BASE_URL not set");
  process.exit(0);
}

const run = async () => {
  const client = createGatewayClient(baseUrl);
  const response = await client.getCapabilities();
  if (!response.network || typeof response.selfFundedOnboarding?.enabled !== "boolean") {
    throw new Error("capabilities_shape_invalid");
  }
  console.log("ok - capabilities shape valid");
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
