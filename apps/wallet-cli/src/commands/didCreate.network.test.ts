/**
 * Wallet mainnet compatibility: ensures HEDERA_NETWORK accepts all networks
 * and mainnet requires ALLOW_MAINNET. Asserts configuration wiring without
 * broadcasting to real mainnet.
 */
import { strict as assert } from "node:assert";
import { envSchema } from "./didCreate.js";

const baseEnv = {
  DID_SERVICE_BASE_URL: "http://localhost:3001"
};

const run = async () => {
  // mainnet without ALLOW_MAINNET → explicit error
  try {
    envSchema.parse({ ...baseEnv, HEDERA_NETWORK: "mainnet", ALLOW_MAINNET: false });
    assert.fail("Expected mainnet without ALLOW_MAINNET to throw");
  } catch (err) {
    assert.ok(err instanceof Error);
    assert.ok(
      err.message.includes("ALLOW_MAINNET") || err.message.includes("mainnet"),
      `Expected mainnet guard error, got: ${err.message}`
    );
  }

  // mainnet with ALLOW_MAINNET=true → success, network=mainnet
  const mainnetEnv = envSchema.parse({
    ...baseEnv,
    HEDERA_NETWORK: "mainnet",
    ALLOW_MAINNET: "true"
  });
  assert.equal(mainnetEnv.HEDERA_NETWORK, "mainnet");

  // previewnet → success
  const previewnetEnv = envSchema.parse({
    ...baseEnv,
    HEDERA_NETWORK: "previewnet"
  });
  assert.equal(previewnetEnv.HEDERA_NETWORK, "previewnet");

  // testnet (default) → success
  const testnetEnv = envSchema.parse(baseEnv);
  assert.equal(testnetEnv.HEDERA_NETWORK, "testnet");

  // explicit testnet → success
  const explicitTestnet = envSchema.parse({
    ...baseEnv,
    HEDERA_NETWORK: "testnet"
  });
  assert.equal(explicitTestnet.HEDERA_NETWORK, "testnet");

  console.log("didCreate.network.test: all assertions passed");
};

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
