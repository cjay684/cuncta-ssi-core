import path from "node:path";
import { loadConfig, assertSoftwareKeysAllowed } from "./core/config.js";
import { createFileVault } from "./core/vault/fileVault.js";
import { getCredential } from "./core/vault/records.js";
import { createGatewayClient } from "./core/gateway/client.js";
import { buildKbJwtBinding, buildVerifyRequest } from "./core/presentation/index.js";
import { createSoftwareKeyManager } from "./core/keys/softwareKeyManager.js";
import {
  applyDisclosureSelection,
  deriveRequiredDisclosures,
  extractDisclosureOptions
} from "./core/disclosure/index.js";
import {
  checkRelyingPartyStatus,
  rememberRelyingParty,
  computeAudHash,
  formatRelyingPartyLog
} from "./core/relyingParty/index.js";

const parseDisclosureSelection = (
  input: string | undefined,
  options: { id: string; label: string; path?: string }[]
) => {
  if (!input) return [];
  if (input === "all") {
    return options.map((opt) => opt.id);
  }
  const requested = new Set(
    input
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean)
  );
  return options
    .filter(
      (opt) =>
        requested.has(opt.id) || requested.has(opt.label) || (opt.path && requested.has(opt.path))
    )
    .map((opt) => opt.id);
};

const main = async () => {
  const config = loadConfig();
  assertSoftwareKeysAllowed(config);
  const vault = createFileVault({
    baseDir: path.resolve(process.cwd(), "apps", "mobile-wallet"),
    keyMaterial: config.WALLET_VAULT_KEY
  });
  await vault.init();

  const credentialId = process.env.WALLET_CREDENTIAL_ID;
  if (!credentialId) {
    throw new Error("WALLET_CREDENTIAL_ID is required");
  }

  const credential = await getCredential(vault, credentialId);
  if (!credential) {
    throw new Error("credential_not_found");
  }

  const gateway = createGatewayClient(config.APP_GATEWAY_BASE_URL);
  const capabilities = await gateway.getCapabilities();
  if (capabilities.network !== config.HEDERA_NETWORK) {
    throw new Error("network_mismatch");
  }

  const action = process.env.WALLET_VERIFY_ACTION ?? "marketplace.list_item";
  const requirements = await gateway.getRequirements({ action, deviceId: config.deviceId });
  const requirement = requirements.requirements[0];
  if (!requirement) {
    throw new Error("requirements_missing");
  }

  const options = extractDisclosureOptions(credential.sdJwt);
  const selectedFromEnv = parseDisclosureSelection(process.env.WALLET_DISCLOSE, options);
  const derived = deriveRequiredDisclosures({
    requirements,
    options,
    vct: credential.vct
  });
  const selectedIds = selectedFromEnv.length ? selectedFromEnv : derived;
  if (!selectedIds.length) {
    throw new Error("disclosure_selection_required");
  }

  const sdJwtPresentation = applyDisclosureSelection(credential.sdJwt, selectedIds);

  const expiresAtMs = Date.parse(requirements.challenge.expires_at);
  const secondsUntilExpiry = Math.max(0, Math.floor((expiresAtMs - Date.now()) / 1000));
  const ttlSeconds = Math.max(1, Math.min(120, secondsUntilExpiry));
  const didRecord = (await vault.getState()).didRecord;
  if (!didRecord?.holderKeyRef?.id) {
    throw new Error("holder_key_missing");
  }
  const keyManager = createSoftwareKeyManager({ config, vault });

  const aud = requirements.challenge.audience;
  const policyHash =
    requirements.policyId && requirements.version !== undefined
      ? `${requirements.policyId}:${requirements.version}`
      : undefined;
  const audHash = computeAudHash(aud);
  const rpStatus = await checkRelyingPartyStatus(vault, { aud, policyHash });
  const display = (message: string) => {
    process.stdout.write(`${message}\n`);
  };
  const log = (message: string) => {
    console.log(message);
  };
  display(`[wallet] verify_aud=${aud}`);
  log(
    formatRelyingPartyLog({
      audHash: audHash.slice(0, 12),
      firstSeen: rpStatus.firstSeen,
      policyChanged: rpStatus.hashChanged
    })
  );
  if (rpStatus.firstSeen || rpStatus.hashChanged) {
    log(
      `[wallet] relying_party_warning ${JSON.stringify({
        audHash: audHash.slice(0, 12),
        firstSeen: rpStatus.firstSeen,
        policyHashChanged: rpStatus.hashChanged
      })}`
    );
    if (process.env.WALLET_CONFIRM !== "true") {
      throw new Error("relying_party_confirmation_required");
    }
  }

  const kbJwt = await buildKbJwtBinding({
    keyManager,
    holderKeyRef: didRecord.holderKeyRef,
    audience: aud,
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

  await rememberRelyingParty(vault, {
    aud,
    audHash,
    displayName: undefined,
    firstSeenAt: new Date().toISOString(),
    lastSeenAt: new Date().toISOString(),
    policyHash
  });

  const selectedLabels = options
    .filter((opt) => selectedIds.includes(opt.id))
    .map((opt) => opt.label)
    .slice(0, 10);
  console.log(`[wallet] disclosed_fields=${selectedLabels.join(",")}`);
  console.log(`[wallet] verify_result=${result.decision}`);
};

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
