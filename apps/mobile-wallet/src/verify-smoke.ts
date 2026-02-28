import path from "node:path";
import { loadConfig, assertSoftwareKeysAllowed } from "./core/config.js";
import { createFileVault, resolveVaultKey } from "./core/vault/fileVault.js";
import { addCredential, getCredential } from "./core/vault/records.js";
import { createGatewayClient } from "./core/gateway/client.js";
import {
  buildKbJwtBinding,
  buildSdJwtPresentation,
  buildVerifyRequest
} from "./core/presentation/index.js";
import { createSoftwareKeyManager } from "./core/keys/softwareKeyManager.js";

const main = async () => {
  const config = loadConfig();
  assertSoftwareKeysAllowed(config);
  const vaultKey = await resolveVaultKey(config);

  const sdJwt = process.env.WALLET_SD_JWT;
  if (!sdJwt) {
    console.log("skip - WALLET_SD_JWT not set");
    return;
  }

  const vault = createFileVault({
    baseDir: path.resolve(process.cwd(), "apps", "mobile-wallet"),
    keyMaterial: vaultKey
  });
  await vault.init();

  const didRecord = (await vault.getState()).didRecord;
  if (!didRecord?.holderKeyRef?.id) {
    console.log("skip - holder key missing (run DID create first)");
    return;
  }

  const credentialId = await addCredential(vault, {
    sdJwt,
    network: config.HEDERA_NETWORK,
    issuerDid: process.env.WALLET_CREDENTIAL_ISSUER_DID,
    type: process.env.WALLET_CREDENTIAL_TYPE,
    vct: process.env.WALLET_CREDENTIAL_VCT
  });
  const credential = await getCredential(vault, credentialId);
  if (!credential) {
    throw new Error("credential_not_found");
  }

  const gateway = createGatewayClient(config.APP_GATEWAY_BASE_URL);
  const capabilities = await gateway.getCapabilities();
  if (capabilities.network !== config.HEDERA_NETWORK) {
    throw new Error("network_mismatch");
  }

  const action = process.env.WALLET_VERIFY_ACTION ?? "identity.verify";
  const requirements = await gateway.getRequirements({ action, deviceId: config.deviceId });
  const requirement = requirements.requirements[0];
  if (!requirement) {
    throw new Error("requirements_missing");
  }

  const sdJwtPresentation = await buildSdJwtPresentation({
    sdJwt: credential.sdJwt,
    disclosures: requirement.disclosures
  });

  const expiresAtMs = Date.parse(requirements.challenge.expires_at);
  const secondsUntilExpiry = Math.max(0, Math.floor((expiresAtMs - Date.now()) / 1000));
  const ttlSeconds = Math.max(1, Math.min(120, secondsUntilExpiry));
  const keyManager = createSoftwareKeyManager({ config, vault });

  const kbJwt = await buildKbJwtBinding({
    keyManager,
    holderKeyRef: didRecord.holderKeyRef,
    audience: requirements.challenge.audience,
    nonce: requirements.challenge.nonce,
    expiresInSeconds: ttlSeconds,
    sdJwtPresentation
  });

  const verifyPayload = buildVerifyRequest({
    sdJwtPresentation,
    kbJwt,
    nonce: requirements.challenge.nonce,
    audience: requirements.challenge.audience
  });

  const result = await gateway.verifyPresentation({
    action,
    presentation: verifyPayload.presentation,
    nonce: verifyPayload.nonce,
    audience: verifyPayload.audience
  });

  console.log(`[wallet] verify_smoke=${result.decision}`);
};

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
