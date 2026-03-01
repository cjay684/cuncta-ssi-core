import { z } from "zod";
import * as Registrar from "@hiero-did-sdk/registrar";
import { toBase58Multibase } from "../encoding/multibase.js";
import { generateKeypair } from "../crypto/ed25519.js";
import { loadWalletState, saveWalletState, walletPaths } from "../walletStore.js";
import { selectWalletKeyStore } from "@cuncta/wallet-keystore";

const HederaNetwork = z.enum(["testnet", "previewnet", "mainnet"]);

const envSchema = z
  .object({
    NODE_ENV: z.string().optional(),
    DID_SERVICE_BASE_URL: z.string().url().optional(),
    HEDERA_NETWORK: HederaNetwork.default("testnet"),
    ALLOW_MAINNET: z.preprocess((v) => v === "true" || v === "1", z.boolean()).default(false),
    HEDERA_PAYER_ACCOUNT_ID: z.string().optional(),
    HEDERA_PAYER_PRIVATE_KEY: z.string().optional(),
    HEDERA_OPERATOR_ID: z.string().optional(),
    HEDERA_OPERATOR_PRIVATE_KEY: z.string().optional()
  })
  .refine((env) => env.HEDERA_NETWORK !== "mainnet" || env.ALLOW_MAINNET, {
    message: "HEDERA_NETWORK=mainnet requires ALLOW_MAINNET=true",
    path: ["ALLOW_MAINNET"]
  });

type WalletState = {
  keys?: { holder?: { alg: "Ed25519"; publicKeyBase64: string; publicKeyMultibase: string } };
  recovery?: { installedAt: string; publicKeyMultibase: string };
  did?: { did?: string };
};

const registrarModule = Registrar as unknown as { default?: typeof Registrar };
const registrar = registrarModule.default ?? Registrar;
type RegistrarProviders = Parameters<typeof registrar.generateCreateDIDRequest>[1];

type RegistrarUpdateRequest = {
  states: unknown[];
  signingRequests?: Record<string, { serializedPayload?: Uint8Array }>;
};

const registrarGenerateUpdateRequest = async (
  input: { did: string; updates: unknown[] },
  providers: RegistrarProviders
): Promise<RegistrarUpdateRequest> => {
  const fn = (
    registrar as unknown as {
      generateUpdateDIDRequest?: (a: unknown, b: unknown) => Promise<unknown>;
    }
  ).generateUpdateDIDRequest;
  if (!fn) throw new Error("did_update_not_supported");
  return (await fn(input, providers)) as RegistrarUpdateRequest;
};

const registrarSubmitUpdateRequest = async (
  input: {
    states: unknown[];
    signatures: Record<string, Uint8Array>;
    waitForDIDVisibility: boolean;
    visibilityTimeoutMs: number;
  },
  providers: RegistrarProviders
): Promise<unknown> => {
  const fn = (
    registrar as unknown as {
      submitUpdateDIDRequest?: (a: unknown, b: unknown) => Promise<unknown>;
    }
  ).submitUpdateDIDRequest;
  if (!fn) throw new Error("did_update_not_supported");
  return await fn(input, providers);
};

const resolvePayer = (env: z.infer<typeof envSchema>) => {
  const payerAccountId = env.HEDERA_PAYER_ACCOUNT_ID?.trim();
  const payerPrivateKey = env.HEDERA_PAYER_PRIVATE_KEY?.trim();
  if (payerAccountId && payerPrivateKey) {
    return { payerAccountId, payerPrivateKey };
  }
  const nodeEnv = env.NODE_ENV ?? process.env.NODE_ENV ?? "development";
  if (nodeEnv === "production" || env.HEDERA_NETWORK !== "testnet") {
    throw new Error("payer_credentials_required");
  }
  const operatorAccountId = env.HEDERA_OPERATOR_ID?.trim();
  const operatorPrivateKey = env.HEDERA_OPERATOR_PRIVATE_KEY?.trim();
  if (!operatorAccountId || !operatorPrivateKey) {
    throw new Error("payer_credentials_required");
  }
  console.warn("Using operator credentials as payer (testnet/dev only)");
  return { payerAccountId: operatorAccountId, payerPrivateKey: operatorPrivateKey };
};

const normalizeMethodId = (value: string) => {
  const hashIndex = value.indexOf("#");
  if (hashIndex !== -1) {
    return `#${value.slice(hashIndex + 1)}`;
  }
  return value.startsWith("#") ? value : `#${value}`;
};

const fetchDidFirstMethodId = async (didServiceBaseUrl: string, did: string) => {
  const resolved = await fetch(
    new URL(`/v1/dids/resolve/${encodeURIComponent(did)}`, didServiceBaseUrl),
    {
      method: "GET"
    }
  );
  if (!resolved.ok) throw new Error("did_resolve_failed");
  const payload = (await resolved.json()) as { didDocument?: Record<string, unknown> };
  const methods = Array.isArray(payload.didDocument?.verificationMethod)
    ? (payload.didDocument?.verificationMethod as Array<Record<string, unknown>>)
    : [];
  const firstMethodId =
    methods.length && typeof methods[0]?.id === "string" ? (methods[0].id as string) : "";
  return firstMethodId ? normalizeMethodId(firstMethodId) : "";
};

const parseRecoveryCooldownSeconds = () => {
  const raw = (process.env.RECOVERY_COOLDOWN_SECONDS ?? "").trim();
  const parsed = raw ? Number(raw) : NaN;
  const nodeEnv = (process.env.NODE_ENV ?? "development").trim();
  // Production default: non-zero.
  if (!Number.isFinite(parsed)) {
    return nodeEnv === "production" ? 3600 : 0;
  }
  return Math.max(0, Math.floor(parsed));
};

export const didRecoverySetup = async () => {
  const env = envSchema.parse(process.env);
  const state = (await loadWalletState()) as unknown as WalletState;
  const did = state.did?.did;
  if (!did) throw new Error("holder_did_missing");
  if (!env.DID_SERVICE_BASE_URL)
    throw new Error("DID_SERVICE_BASE_URL required for recovery setup");

  const keystore = selectWalletKeyStore({ walletDir: walletPaths.walletDir() });
  if (state.recovery?.publicKeyMultibase) {
    console.log(JSON.stringify({ ok: true, did, recoveryAlreadyPresent: true }, null, 2));
    return;
  }

  // Mint (or load) a dedicated recovery key. Private key material stays in the keystore.
  await keystore.deleteKey("recovery");
  const recoveryKey = await keystore.ensureKey("recovery");
  const recoveryPublicKeyMultibase = toBase58Multibase(recoveryKey.publicKey);
  const recoveryId = `#recovery-${Date.now()}`;

  const { payerAccountId, payerPrivateKey } = resolvePayer(env);
  const providers = {
    clientOptions: {
      network: env.HEDERA_NETWORK,
      accountId: payerAccountId,
      privateKey: payerPrivateKey
    }
  } as RegistrarProviders;

  const updates: Array<Record<string, unknown>> = [
    {
      operation: "add-verification-method",
      id: recoveryId,
      property: "verificationMethod",
      publicKeyMultibase: recoveryPublicKeyMultibase
    },
    // Recovery key must be authorized to sign a DID update when primary is lost.
    {
      operation: "add-verification-method",
      id: recoveryId,
      property: "authentication",
      publicKeyMultibase: recoveryPublicKeyMultibase
    },
    {
      operation: "add-verification-method",
      id: recoveryId,
      property: "assertionMethod",
      publicKeyMultibase: recoveryPublicKeyMultibase
    }
  ];

  const updateReq = await registrarGenerateUpdateRequest({ did, updates }, providers);
  const signingRequests = (updateReq?.signingRequests ?? {}) as Record<
    string,
    { serializedPayload?: Uint8Array }
  >;
  const signatures: Record<string, Uint8Array> = {};
  for (const [key, req] of Object.entries(signingRequests)) {
    const payloadToSign = (req.serializedPayload ?? new Uint8Array()) as Uint8Array;
    signatures[key] = await keystore.sign("primary", payloadToSign);
  }
  await registrarSubmitUpdateRequest(
    {
      states: updateReq.states,
      signatures,
      waitForDIDVisibility: false,
      visibilityTimeoutMs: 120_000
    },
    providers
  );

  state.recovery = {
    installedAt: new Date().toISOString(),
    publicKeyMultibase: recoveryPublicKeyMultibase
  };
  await saveWalletState(state as unknown as never);

  console.log(
    JSON.stringify(
      { ok: true, did, recoveryInstalled: true, recoveryMethodId: recoveryId },
      null,
      2
    )
  );
};

export const didRecoverySimulateLoss = async () => {
  const state = (await loadWalletState()) as unknown as WalletState;
  const did = state.did?.did;
  if (!did) throw new Error("holder_did_missing");
  if (!state.keys?.holder) {
    console.log(JSON.stringify({ ok: true, did, primaryAlreadyMissing: true }, null, 2));
    return;
  }
  const next = {
    ...state,
    keys: { ...(state.keys ?? {}) }
  } as WalletState;
  delete next.keys!.holder;
  await saveWalletState(next as unknown as never);
  console.log(JSON.stringify({ ok: true, did, simulatedLoss: true }, null, 2));
};

export const didRecoveryRotate = async () => {
  const env = envSchema.parse(process.env);
  const state = (await loadWalletState()) as unknown as WalletState;
  const did = state.did?.did;
  if (!did) throw new Error("holder_did_missing");
  if (!env.DID_SERVICE_BASE_URL)
    throw new Error("DID_SERVICE_BASE_URL required for recovery rotate");
  const cooldownSeconds = parseRecoveryCooldownSeconds();
  if ((process.env.NODE_ENV ?? "development") === "production" && cooldownSeconds > 0) {
    const installedAt = state.recovery?.installedAt ?? "";
    const installedMs = installedAt ? Date.parse(installedAt) : NaN;
    if (!Number.isFinite(installedMs)) {
      throw new Error("recovery_state_missing_installedAt");
    }
    const elapsedSeconds = Math.floor((Date.now() - installedMs) / 1000);
    if (elapsedSeconds < cooldownSeconds) {
      throw new Error("recovery_cooldown_active");
    }
  }

  const keystore = selectWalletKeyStore({ walletDir: walletPaths.walletDir() });
  const recoveryKey = await keystore.loadKey("recovery");
  if (!recoveryKey) throw new Error("recovery_key_missing");

  const removeId = await fetchDidFirstMethodId(env.DID_SERVICE_BASE_URL, did);
  const nextKeypair = await generateKeypair();
  const nextPublicKeyMultibase = toBase58Multibase(nextKeypair.publicKey);
  const nextId = `#key-${Date.now()}`;

  const updates: Array<Record<string, unknown>> = [
    {
      operation: "add-verification-method",
      id: nextId,
      property: "verificationMethod",
      publicKeyMultibase: nextPublicKeyMultibase
    },
    {
      operation: "add-verification-method",
      id: nextId,
      property: "authentication",
      publicKeyMultibase: nextPublicKeyMultibase
    },
    {
      operation: "add-verification-method",
      id: nextId,
      property: "assertionMethod",
      publicKeyMultibase: nextPublicKeyMultibase
    }
  ];
  if (removeId) {
    updates.push({ operation: "remove-verification-method", id: removeId });
  }

  const { payerAccountId, payerPrivateKey } = resolvePayer(env);
  const providers = {
    clientOptions: {
      network: env.HEDERA_NETWORK,
      accountId: payerAccountId,
      privateKey: payerPrivateKey
    }
  } as RegistrarProviders;

  const updateReq = await registrarGenerateUpdateRequest({ did, updates }, providers);
  const signingRequests = (updateReq?.signingRequests ?? {}) as Record<
    string,
    { serializedPayload?: Uint8Array }
  >;
  const signatures: Record<string, Uint8Array> = {};
  for (const [key, req] of Object.entries(signingRequests)) {
    const payloadToSign = (req.serializedPayload ?? new Uint8Array()) as Uint8Array;
    signatures[key] = await keystore.sign("recovery", payloadToSign);
  }
  await registrarSubmitUpdateRequest(
    {
      states: updateReq.states,
      signatures,
      waitForDIDVisibility: false,
      visibilityTimeoutMs: 120_000
    },
    providers
  );

  if (typeof keystore.saveKeyMaterial !== "function") {
    throw new Error("keystore_rotation_not_supported");
  }
  await keystore.saveKeyMaterial({
    purpose: "primary",
    alg: "Ed25519",
    privateKey: nextKeypair.privateKey,
    publicKey: nextKeypair.publicKey,
    publicKeyMultibase: nextPublicKeyMultibase
  });
  // Reload to preserve keystore updates written by saveKeyMaterial().
  const refreshed = (await loadWalletState()) as unknown as WalletState;
  const nextState = {
    ...refreshed,
    keys: {
      ...(refreshed.keys ?? {}),
      holder: {
        alg: "Ed25519",
        publicKeyBase64: Buffer.from(nextKeypair.publicKey).toString("base64"),
        publicKeyMultibase: nextPublicKeyMultibase
      }
    }
  } as WalletState;
  await saveWalletState(nextState as unknown as never);

  console.log(
    JSON.stringify(
      {
        ok: true,
        did,
        rotated: true,
        removed: removeId || null,
        newMethodId: nextId,
        recoveryUsed: true
      },
      null,
      2
    )
  );
};
