import path from "node:path";
import { loadConfig, assertSoftwareKeysAllowed } from "./core/config.js";
import { createFileVault, resolveVaultKey } from "./core/vault/fileVault.js";
import { createSoftwareKeyManager } from "./core/keys/softwareKeyManager.js";
import { createGatewayClient } from "./core/gateway/client.js";
import { setPayerRecord } from "./core/vault/records.js";
import { createDidViaGatewayUserPays } from "./core/did/createDid.js";
import { resolveDidWithGateway } from "./core/did/resolveDid.js";
import { createPayerManager } from "./core/payer/payerManager.js";

const main = async () => {
  const config = loadConfig();
  assertSoftwareKeysAllowed(config);
  console.log(`[wallet] network=${config.HEDERA_NETWORK} gateway=${config.APP_GATEWAY_BASE_URL}`);
  const vaultKey = await resolveVaultKey(config);

  const vault = createFileVault({
    baseDir: path.resolve(process.cwd(), "apps", "mobile-wallet"),
    keyMaterial: vaultKey
  });
  await vault.init();

  const keyManager = createSoftwareKeyManager({ config, vault });
  const payerManager = createPayerManager({ keyManager });
  const payer = await payerManager.importFromEnvironmentAndQueryBalance();
  console.log(`[wallet] payer_balance_tinybars=${payer.balanceTinybars}`);
  await setPayerRecord(vault, {
    payerRef: payer.payerRef,
    accountId: payer.accountId,
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
