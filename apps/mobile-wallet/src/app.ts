import path from "node:path";
import { loadConfig, assertSoftwareKeysAllowed } from "./core/config.js";
import { createFileVault } from "./core/vault/fileVault.js";
import { createSoftwareKeyManager } from "./core/keys/softwareKeyManager.js";
import { createGatewayClient } from "./core/gateway/client.js";
import { setPayerRecord } from "./core/vault/records.js";
import { createDidViaGatewayUserPays } from "./core/did/createDid.js";
import { resolveDidWithGateway } from "./core/did/resolveDid.js";

const main = async () => {
  const config = loadConfig();
  assertSoftwareKeysAllowed(config);
  console.log(`[wallet] network=${config.HEDERA_NETWORK} gateway=${config.APP_GATEWAY_BASE_URL}`);

  const vault = createFileVault({
    baseDir: path.resolve(process.cwd(), "apps", "mobile-wallet"),
    keyMaterial: config.WALLET_VAULT_KEY
  });
  await vault.init();

  const keyManager = createSoftwareKeyManager({ config, vault });

  const payerAccountId = process.env.HEDERA_PAYER_ACCOUNT_ID;
  const payerPrivateKey = process.env.HEDERA_PAYER_PRIVATE_KEY;
  if (!payerAccountId || !payerPrivateKey) {
    throw new Error("missing_payer_credentials");
  }

  const payerRef = await keyManager.importOrSetPayerKey({
    accountId: payerAccountId,
    privateKey: payerPrivateKey
  });
  await setPayerRecord(vault, {
    payerRef,
    accountId: payerAccountId,
    network: config.HEDERA_NETWORK
  });

  const gateway = createGatewayClient(config.APP_GATEWAY_BASE_URL);
  const capabilities = await gateway.getCapabilities();
  console.log(
    `[wallet] capabilities selfFunded=${capabilities.selfFundedOnboarding.enabled} network=${capabilities.network}`
  );

  const result = await createDidViaGatewayUserPays({
    config,
    keyManager,
    vault
  });
  console.log(`[wallet] did=${result.did} tx=${result.transactionId}`);

  const resolved = await resolveDidWithGateway({
    baseUrl: config.APP_GATEWAY_BASE_URL,
    did: result.did,
    maxAttempts: 60,
    intervalMs: 4000
  });
  console.log(`[wallet] resolved in ${resolved.attempts} attempts`);
};

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
