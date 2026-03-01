import { z } from "zod";
import { randomUUID } from "node:crypto";
import * as Registrar from "@hiero-did-sdk/registrar";
import * as DidMessages from "@hiero-did-sdk/messages";
import {
  classifyHederaFailure,
  OnboardingStrategy,
  parseOnboardingStrategyList
} from "@cuncta/shared";
import {
  AccountId,
  Client,
  Hbar,
  PrivateKey,
  PublicKey,
  TopicMessageSubmitTransaction,
  TransactionId
} from "@hashgraph/sdk";
import { toBase58Multibase } from "../encoding/multibase.js";
import { sha256Hex } from "../crypto/ed25519.js";
import {
  loadWalletState as loadWalletStateShared,
  saveWalletState as saveWalletStateShared,
  walletPaths
} from "../walletStore.js";
import { selectWalletKeyStore } from "@cuncta/wallet-keystore";

const HederaNetwork = z.enum(["testnet", "previewnet", "mainnet"]);
export type HederaNetworkType = z.infer<typeof HederaNetwork>;

export const envSchema = z
  .object({
    NODE_ENV: z.string().optional(),
    DID_SERVICE_BASE_URL: z.string().url(),
    APP_GATEWAY_BASE_URL: z.preprocess(
      (value) => (value === "" ? undefined : value),
      z.string().url().optional()
    ),
    HEDERA_NETWORK: HederaNetwork.default("testnet"),
    ALLOW_MAINNET: z.preprocess((v) => v === "true" || v === "1", z.boolean()).default(false),
    HEDERA_DID_TOPIC_ID: z.string().optional(),
    HEDERA_PAYER_ACCOUNT_ID: z.string().optional(),
    HEDERA_PAYER_PRIVATE_KEY: z.string().optional(),
    HEDERA_OPERATOR_ID: z.string().optional(),
    HEDERA_OPERATOR_PRIVATE_KEY: z.string().optional(),
    ONBOARDING_STRATEGY_DEFAULT: z.string().optional(),
    ONBOARDING_STRATEGY_ALLOWED: z.string().optional()
  })
  .refine((env) => env.HEDERA_NETWORK !== "mainnet" || env.ALLOW_MAINNET, {
    message: "HEDERA_NETWORK=mainnet requires ALLOW_MAINNET=true",
    path: ["ALLOW_MAINNET"]
  });

type WalletState = {
  keys: {
    holder: {
      alg: "Ed25519";
      publicKeyBase64: string;
      publicKeyMultibase: string;
    };
  };
  credentials?: Array<{
    vct: string;
    sdJwt: string;
    credentialId: string;
  }>;
  did: {
    did: string;
    topicId: string;
    transactionId: string;
  };
};

const saveWalletState = async (state: WalletState) => {
  await saveWalletStateShared(state as unknown as never);
};

const loadWalletState = async (): Promise<WalletState | null> => {
  const loaded = await loadWalletStateShared().catch(() => null);
  if (!loaded) return null;
  return loaded as unknown as WalletState;
};

const userPaysRequestResponseSchema = z.object({
  handoffToken: z.string().min(10),
  expiresAt: z.string(),
  network: z.enum(["testnet", "previewnet", "mainnet"]),
  topicId: z.string(),
  publicKeyMultibase: z.string(),
  options: z.object({
    topicManagement: z.enum(["shared", "single"]),
    includeServiceEndpoints: z.boolean()
  })
});

const userPaysSubmitResponseSchema = z.object({
  transactionId: z.string().optional(),
  status: z.string().optional(),
  requestId: z.string().optional()
});

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
) => {
  const fn = (
    registrar as unknown as {
      submitUpdateDIDRequest?: (a: unknown, b: unknown) => Promise<unknown>;
    }
  ).submitUpdateDIDRequest;
  if (!fn) throw new Error("did_update_not_supported");
  return await fn(input, providers);
};

const sleepMs = async (ms: number) => {
  await new Promise((resolve) => setTimeout(resolve, ms));
};

const jitteredBackoffMs = (attempt: number, baseDelayMs: number, maxDelayMs: number) => {
  const raw = Math.min(maxDelayMs, baseDelayMs * 2 ** Math.max(0, attempt - 1));
  const jitter = raw * 0.2 * (Math.random() * 2 - 1);
  return Math.max(0, Math.round(raw + jitter));
};

const runWithHederaRetries = async <T>(input: {
  label: string;
  maxAttempts?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  fn: (attempt: number) => Promise<T>;
}): Promise<T> => {
  const maxAttempts = input.maxAttempts ?? 3;
  const baseDelayMs = input.baseDelayMs ?? 500;
  const maxDelayMs = input.maxDelayMs ?? 4000;
  let lastError: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      return await input.fn(attempt);
    } catch (error) {
      lastError = error;
      const classification = classifyHederaFailure(error);
      console.warn(
        `[hedera.retry] ${JSON.stringify({
          label: input.label,
          attempt,
          maxAttempts,
          kind: classification.kind,
          code: classification.code,
          status: classification.status,
          txId: classification.txId
        })}`
      );
      if (classification.kind === "deterministic") throw error;
      if (attempt === maxAttempts) break;
      await sleepMs(jitteredBackoffMs(attempt, baseDelayMs, maxDelayMs));
    }
  }
  const classification = classifyHederaFailure(lastError);
  throw new Error(
    `hedera_operation_failed_after_retries:${JSON.stringify({
      label: input.label,
      attempts: maxAttempts,
      kind: classification.kind,
      code: classification.code,
      status: classification.status,
      txId: classification.txId
    })}`
  );
};

const DIDOwnerMessageCtor =
  (DidMessages as unknown as { DIDOwnerMessage?: unknown }).DIDOwnerMessage ??
  (DidMessages as unknown as { default?: { DIDOwnerMessage?: unknown } }).default?.DIDOwnerMessage;
if (!DIDOwnerMessageCtor) {
  throw new Error("hiero_messages_missing:DIDOwnerMessage");
}

const parseTopicIdFromDid = (did: string) => {
  const parts = did.split("_");
  if (parts.length < 2) return "";
  return parts[parts.length - 1] ?? "";
};

const waitForDidResolution = async (
  didServiceBaseUrl: string,
  did: string,
  options: { maxAttempts?: number; intervalMs?: number } = {}
) => {
  const started = Date.now();
  const maxAttempts = options.maxAttempts ?? 60;
  const intervalMs = options.intervalMs ?? 4000;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const elapsedMs = Date.now() - started;
    console.log(
      `did_resolution_poll attempt=${attempt}/${maxAttempts} elapsedMs=${elapsedMs} intervalMs=${intervalMs}`
    );
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort("did_resolution_fetch_timeout"), 5000);
      timeout.unref?.();
      const response = await fetch(
        new URL(`/v1/dids/resolve/${encodeURIComponent(did)}`, didServiceBaseUrl),
        {
          signal: controller.signal
        }
      );
      clearTimeout(timeout);
      console.log(
        `did_resolution_fetch attempt=${attempt}/${maxAttempts} status=${response.status}`
      );
      if (response.ok) {
        const payload = (await response.json()) as { didDocument?: Record<string, unknown> };
        if (payload.didDocument && Object.keys(payload.didDocument).length > 0) {
          return { elapsedMs: Date.now() - started, attempts: attempt };
        }
      }
    } catch {
      // ignore until timeout
    }
    console.log(`did_resolution_wait attempt=${attempt}/${maxAttempts} sleepMs=${intervalMs}`);
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new Error(`Timed out waiting for DID resolution: ${did}`);
};

const createDidUserPaysViaGateway = async (input: {
  gatewayBaseUrl: string;
  network: HederaNetworkType;
  publicKey: Uint8Array;
  publicKeyMultibase: string;
  sign: (payload: Uint8Array) => Promise<Uint8Array>;
  payerAccountId: string;
  payerPrivateKey: string;
  topicId?: string;
  maxFeeTinybars: number;
}) => {
  const deviceId = randomUUID();
  const requestResponse = await fetch(
    new URL("/v1/onboard/did/create/user-pays/request", input.gatewayBaseUrl),
    {
      method: "POST",
      headers: { "content-type": "application/json", "x-device-id": deviceId },
      body: JSON.stringify({
        network: input.network,
        publicKeyMultibase: input.publicKeyMultibase,
        topicId: input.topicId,
        options: { topicManagement: "shared", includeServiceEndpoints: true }
      })
    }
  );
  if (!requestResponse.ok) {
    const bodyText = await requestResponse.text();
    let payload: { error?: string; message?: string } | null = null;
    try {
      payload = JSON.parse(bodyText) as { error?: string; message?: string };
    } catch {
      payload = null;
    }
    if (payload?.error === "self_funded_onboarding_disabled") {
      const err = new Error("self_funded_onboarding_disabled");
      (err as { code?: string }).code = "self_funded_onboarding_disabled";
      throw err;
    }
    throw new Error(`gateway user-pays request failed: ${payload?.message ?? bodyText}`);
  }
  const requestPayload = userPaysRequestResponseSchema.parse(await requestResponse.json());
  if (requestPayload.publicKeyMultibase !== input.publicKeyMultibase) {
    throw new Error("publicKeyMultibase mismatch in user-pays request.");
  }
  if (requestPayload.network !== input.network) {
    throw new Error("network mismatch in user-pays request.");
  }

  const publicKey = PublicKey.fromBytesED25519(input.publicKey);
  const message = new (DIDOwnerMessageCtor as new (input: {
    publicKey: PublicKey;
    network: string;
    topicId: string;
  }) => {
    did: string;
    messageBytes: Uint8Array;
    signature?: Uint8Array;
    payload: Uint8Array;
  })({
    publicKey,
    network: requestPayload.network,
    topicId: requestPayload.topicId
  });
  const signature = await input.sign(message.messageBytes);
  message.signature = signature;
  const payload = message.payload;

  const client = Client.forName(requestPayload.network);
  const payerAccount = AccountId.fromString(input.payerAccountId);
  const payerKey = PrivateKey.fromString(input.payerPrivateKey);
  const transaction = new TopicMessageSubmitTransaction()
    .setTopicId(requestPayload.topicId)
    .setMessage(payload)
    .setTransactionId(TransactionId.generate(payerAccount))
    .setMaxTransactionFee(Hbar.fromTinybars(input.maxFeeTinybars))
    .freezeWith(client);
  const signed = await transaction.sign(payerKey);
  const signedBytes = signed.toBytes();
  if (typeof client.close === "function") {
    client.close();
  }

  const submitResponse = await fetch(
    new URL("/v1/onboard/did/create/user-pays/submit", input.gatewayBaseUrl),
    {
      method: "POST",
      headers: { "content-type": "application/json", "x-device-id": deviceId },
      body: JSON.stringify({
        handoffToken: requestPayload.handoffToken,
        signedTransactionB64u: Buffer.from(signedBytes).toString("base64url")
      })
    }
  );
  if (!submitResponse.ok) {
    const bodyText = await submitResponse.text();
    let payload: { error?: string; message?: string } | null = null;
    try {
      payload = JSON.parse(bodyText) as { error?: string; message?: string };
    } catch {
      payload = null;
    }
    if (payload?.error === "self_funded_onboarding_disabled") {
      const err = new Error("self_funded_onboarding_disabled");
      (err as { code?: string }).code = "self_funded_onboarding_disabled";
      throw err;
    }
    throw new Error(`gateway user-pays submit failed: ${payload?.message ?? bodyText}`);
  }
  const submitPayload = userPaysSubmitResponseSchema.parse(await submitResponse.json());
  return {
    did: message.did,
    topicId: requestPayload.topicId,
    transactionId: submitPayload.transactionId ?? ""
  };
};

const createDidUserPays = async (input: {
  network: HederaNetworkType;
  payerAccountId: string;
  payerPrivateKey: string;
  publicKeyMultibase: string;
  sign: (payload: Uint8Array) => Promise<Uint8Array>;
  didServiceBaseUrl: string;
  topicId?: string;
}) => {
  const providers = {
    clientOptions: {
      network: input.network,
      accountId: input.payerAccountId,
      privateKey: input.payerPrivateKey
    }
  } as RegistrarProviders;
  return await runWithHederaRetries({
    label: "did_create_user_pays",
    fn: async () => {
      const createResult = await registrar.generateCreateDIDRequest(
        {
          multibasePublicKey: input.publicKeyMultibase,
          topicId: input.topicId
        },
        providers
      );
      const payloadToSign = createResult.signingRequest.serializedPayload;
      const signature = await input.sign(payloadToSign);
      console.log(`payloadSha256=${sha256Hex(payloadToSign)}`);
      console.log(`signatureSha256=${sha256Hex(signature)}`);
      const submitResult = await registrar.submitCreateDIDRequest(
        {
          state: createResult.state as Registrar.SubmitCreateDIDRequestOptions["state"],
          signature,
          waitForDIDVisibility: false,
          visibilityTimeoutMs: 120_000
        },
        providers
      );
      const did = submitResult.did;
      console.log("Pending network confirmation...");
      await waitForDidResolution(input.didServiceBaseUrl, did);
      return {
        did,
        topicId: parseTopicIdFromDid(did),
        transactionId: (submitResult as { transactionId?: string }).transactionId ?? ""
      };
    }
  });
};

const resolveStrategy = (input: {
  allowed: string | undefined;
  requested?: OnboardingStrategy;
  fallback: OnboardingStrategy;
}): OnboardingStrategy => {
  const allowed = parseOnboardingStrategyList(input.allowed);
  const fallback =
    allowed.length > 0 && !allowed.includes(input.fallback) ? allowed[0]! : input.fallback;
  if (!input.requested) {
    return fallback;
  }
  if (allowed.length > 0 && !allowed.includes(input.requested)) {
    return fallback;
  }
  return input.requested;
};

const assertNoOperatorFallbackInProd = (env: z.infer<typeof envSchema>) => {
  const nodeEnv = env.NODE_ENV ?? process.env.NODE_ENV ?? "development";
  const network = env.HEDERA_NETWORK;
  if (nodeEnv !== "production" && network === "testnet") {
    return;
  }
  const payerAccountId = env.HEDERA_PAYER_ACCOUNT_ID?.trim();
  const payerPrivateKey = env.HEDERA_PAYER_PRIVATE_KEY?.trim();
  if (!payerAccountId || !payerPrivateKey) {
    throw new Error("operator_as_payer_disabled_in_production");
  }
};

let warnedOperatorFallback = false;
const warnOperatorFallback = () => {
  if (warnedOperatorFallback) return;
  warnedOperatorFallback = true;
  console.warn("Using operator credentials as payer (testnet/dev only)");
};

const isCiTestBuildEnabled = () => {
  const buildFlag = (globalThis as { __CI_TEST_BUILD__?: unknown }).__CI_TEST_BUILD__;
  return buildFlag === true || (process.env.CI_TEST_MODE ?? "").trim() === "true";
};

const resolvePayerCredentials = (env: z.infer<typeof envSchema>) => {
  const payerAccountId = env.HEDERA_PAYER_ACCOUNT_ID?.trim();
  const payerPrivateKey = env.HEDERA_PAYER_PRIVATE_KEY?.trim();
  // #region agent log
  fetch("http://127.0.0.1:7699/ingest/ffc49d57-354d-40f6-8f22-e1def74475d1", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "6783de" },
    body: JSON.stringify({
      sessionId: "6783de",
      runId: process.env.DEBUG_RUN_ID ?? "baseline",
      hypothesisId: "H1",
      location: "apps/wallet-cli/src/commands/didCreate.ts:resolvePayerCredentials",
      message: "wallet-cli payer credentials path check",
      data: {
        hasDirectPayerCredentials: Boolean(payerAccountId && payerPrivateKey),
        nodeEnv: env.NODE_ENV ?? process.env.NODE_ENV ?? "development",
        network: env.HEDERA_NETWORK,
        ciTestBuildEnabled: isCiTestBuildEnabled()
      },
      timestamp: Date.now()
    })
  }).catch(() => {});
  // #endregion
  if (payerAccountId && payerPrivateKey) {
    return { payerAccountId, payerPrivateKey, usedFallback: false };
  }
  const nodeEnv = env.NODE_ENV ?? process.env.NODE_ENV ?? "development";
  const network = env.HEDERA_NETWORK;
  if (nodeEnv === "production" || network !== "testnet") {
    throw new Error(
      "Missing HEDERA_PAYER_ACCOUNT_ID or HEDERA_PAYER_PRIVATE_KEY (required outside testnet/dev)"
    );
  }
  if (!isCiTestBuildEnabled()) {
    throw new Error(
      "payer_credentials_required (set HEDERA_PAYER_*; operator fallback requires CI_TEST_MODE=true)"
    );
  }
  const operatorAccountId = env.HEDERA_OPERATOR_ID?.trim();
  const operatorPrivateKey = env.HEDERA_OPERATOR_PRIVATE_KEY?.trim();
  // #region agent log
  fetch("http://127.0.0.1:7699/ingest/ffc49d57-354d-40f6-8f22-e1def74475d1", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "6783de" },
    body: JSON.stringify({
      sessionId: "6783de",
      runId: process.env.DEBUG_RUN_ID ?? "baseline",
      hypothesisId: "H1",
      location: "apps/wallet-cli/src/commands/didCreate.ts:resolvePayerCredentialsFallback",
      message: "wallet-cli fallback branch reached",
      data: {
        hasOperatorCredentials: Boolean(operatorAccountId && operatorPrivateKey),
        network: env.HEDERA_NETWORK
      },
      timestamp: Date.now()
    })
  }).catch(() => {});
  // #endregion
  if (!operatorAccountId || !operatorPrivateKey) {
    throw new Error("Missing HEDERA_PAYER_* and HEDERA_OPERATOR_* for testnet/dev fallback");
  }
  warnOperatorFallback();
  return {
    payerAccountId: operatorAccountId,
    payerPrivateKey: operatorPrivateKey,
    usedFallback: true
  };
};

const probeGatewayCapabilities = async (gatewayBaseUrl: string) => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 2500);
  try {
    const response = await fetch(new URL("/v1/capabilities", gatewayBaseUrl), {
      method: "GET",
      signal: controller.signal
    });
    if (!response.ok) {
      return null;
    }
    const payload = (await response.json()) as {
      selfFundedOnboarding?: {
        enabled?: boolean;
        maxFeeTinybars?: number;
        feeBudgets?: { TopicMessageSubmitTransaction?: { maxFeeTinybars?: number } };
      };
      network?: string;
    };
    if (!payload || typeof payload !== "object") return null;
    const maxFeeFromBudgets =
      payload.selfFundedOnboarding?.feeBudgets?.TopicMessageSubmitTransaction?.maxFeeTinybars;
    return {
      selfFundedOnboardingEnabled: Boolean(payload.selfFundedOnboarding?.enabled),
      selfFundedMaxFeeTinybars:
        typeof maxFeeFromBudgets === "number"
          ? maxFeeFromBudgets
          : typeof payload.selfFundedOnboarding?.maxFeeTinybars === "number"
            ? payload.selfFundedOnboarding.maxFeeTinybars
            : undefined,
      network: typeof payload.network === "string" ? payload.network : undefined
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
};

export const didCreateAuto = async (modeOverride?: OnboardingStrategy) => {
  const commandStarted = Date.now();
  process.stdout.write("stage=did.create.auto|event=start|elapsedMs=0\n");
  const commandHeartbeat = setInterval(() => {
    console.log(`stage=did.create.auto|event=heartbeat|elapsedMs=${Date.now() - commandStarted}`);
  }, 5000);
  commandHeartbeat.unref?.();

  try {
    const env = envSchema.parse(process.env);
    const network = env.HEDERA_NETWORK;
    const serviceBaseUrl = env.DID_SERVICE_BASE_URL;
    const gatewayBaseUrl = env.APP_GATEWAY_BASE_URL ?? "http://localhost:3010";
    const defaultStrategy: OnboardingStrategy = "user_pays";
    const strategy = resolveStrategy({
      allowed: env.ONBOARDING_STRATEGY_ALLOWED ?? "user_pays",
      requested: modeOverride,
      fallback: defaultStrategy
    });

    const keystore = selectWalletKeyStore({ walletDir: walletPaths.walletDir() });
    // DID creation should mint fresh key material each time:
    // - `primary`: DID root key (signs DID updates/deactivation)
    // - `holder`: holder binding key (kb-jwt cnf)
    await keystore.deleteKey("primary");
    await keystore.deleteKey("holder");
    const rootKeypair = await keystore.ensureKey("primary");
    const holderKeypair = await keystore.ensureKey("holder");

    const rootPublicKeyMultibase = toBase58Multibase(rootKeypair.publicKey);
    const holderPublicKeyMultibase = toBase58Multibase(holderKeypair.publicKey);
    if (!rootPublicKeyMultibase.startsWith("z") || !holderPublicKeyMultibase.startsWith("z")) {
      throw new Error("publicKeyMultibase must start with 'z'.");
    }

    console.log(`network=${network}`);
    console.log(`onboarding_mode=${strategy}`);

    let result: { did: string; topicId: string; transactionId: string };
    {
      assertNoOperatorFallbackInProd(env);
      const { payerAccountId, payerPrivateKey } = resolvePayerCredentials(env);
      const maxFeeTinybarsLocal = Number(process.env.USER_PAYS_MAX_FEE_TINYBARS ?? 50_000_000);
      if (env.APP_GATEWAY_BASE_URL) {
        const capabilities = await probeGatewayCapabilities(gatewayBaseUrl);
        const canUseGateway =
          capabilities?.selfFundedOnboardingEnabled && capabilities?.network === network;
        const maxFeeTinybars =
          typeof capabilities?.selfFundedMaxFeeTinybars === "number"
            ? Math.min(maxFeeTinybarsLocal, capabilities.selfFundedMaxFeeTinybars)
            : maxFeeTinybarsLocal;
        try {
          if (!canUseGateway) {
            throw new Error("gateway_user_pays_unavailable");
          }
          result = await createDidUserPaysViaGateway({
            gatewayBaseUrl,
            network,
            publicKey: rootKeypair.publicKey,
            publicKeyMultibase: rootPublicKeyMultibase,
            sign: (payload) => keystore.sign("primary", payload),
            payerAccountId,
            payerPrivateKey,
            topicId: env.HEDERA_DID_TOPIC_ID,
            maxFeeTinybars
          });
        } catch (error) {
          const code = error instanceof Error ? (error as { code?: string }).code : undefined;
          if (code !== "self_funded_onboarding_disabled") {
            if ((error as Error).message !== "gateway_user_pays_unavailable") {
              throw error;
            }
          }
          result = await createDidUserPays({
            network,
            payerAccountId,
            payerPrivateKey,
            publicKeyMultibase: rootPublicKeyMultibase,
            sign: (payload) => keystore.sign("primary", payload),
            didServiceBaseUrl: serviceBaseUrl,
            topicId: env.HEDERA_DID_TOPIC_ID
          });
        }
      } else {
        result = await createDidUserPays({
          network,
          payerAccountId,
          payerPrivateKey,
          publicKeyMultibase: rootPublicKeyMultibase,
          sign: (payload) => keystore.sign("primary", payload),
          didServiceBaseUrl: serviceBaseUrl,
          topicId: env.HEDERA_DID_TOPIC_ID
        });
      }
    }

    console.log("Pending network confirmation...");
    const resolveBaseUrl = env.APP_GATEWAY_BASE_URL ?? serviceBaseUrl;
    const resolution = await waitForDidResolution(resolveBaseUrl, result.did);
    console.log(
      `did_resolution_elapsed_ms=${resolution.elapsedMs} attempts=${resolution.attempts}`
    );

    // Install a dedicated holder binding key in the DID Document.
    // This enables true "DID↔cnf" rotation semantics: root key stays for DID updates, holder key rotates for kb-jwt binding.
    {
      const { payerAccountId, payerPrivateKey } = resolvePayerCredentials(env);
      const providers = {
        clientOptions: {
          network: env.HEDERA_NETWORK,
          accountId: payerAccountId,
          privateKey: payerPrivateKey
        }
      } as RegistrarProviders;
      const holderId = `#holder-${Date.now()}`;
      const updates: Array<Record<string, unknown>> = [
        {
          operation: "add-verification-method",
          id: holderId,
          property: "verificationMethod",
          publicKeyMultibase: holderPublicKeyMultibase
        },
        {
          operation: "add-verification-method",
          id: holderId,
          property: "authentication",
          publicKeyMultibase: holderPublicKeyMultibase
        },
        {
          operation: "add-verification-method",
          id: holderId,
          property: "assertionMethod",
          publicKeyMultibase: holderPublicKeyMultibase
        }
      ];
      const updateReq = await registrarGenerateUpdateRequest(
        { did: result.did, updates },
        providers
      );
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
      // Deterministic visibility poll (no blind sleeps): ensure the holder key is now authorized by the DID doc.
      await waitForDidResolution(resolveBaseUrl, result.did, { maxAttempts: 90, intervalMs: 4000 });
    }

    const existing = await loadWalletState();
    const state: WalletState = {
      // Preserve keystore + any future wallet metadata.
      // (File keystore writes private key material under `state.keystore.*`; do not wipe it.)
      ...(existing ?? {}),
      keys: {
        holder: {
          alg: "Ed25519",
          publicKeyBase64: Buffer.from(holderKeypair.publicKey).toString("base64"),
          publicKeyMultibase: holderPublicKeyMultibase
        }
      },
      credentials: existing?.credentials ?? [],
      did: {
        did: result.did,
        topicId: result.topicId,
        transactionId: result.transactionId
      }
    };

    await saveWalletState(state);
    console.log(`did=${result.did}`);
  } finally {
    clearInterval(commandHeartbeat);
  }
};

export const didCreateUserPays = async () => {
  await didCreateAuto("user_pays");
};

export const didCreateUserPaysGateway = async () => {
  const env = envSchema.parse(process.env);
  const network = env.HEDERA_NETWORK;
  if (!env.APP_GATEWAY_BASE_URL) {
    throw new Error("APP_GATEWAY_BASE_URL is required for gateway user-pays");
  }
  console.log(`network=${network}`);
  assertNoOperatorFallbackInProd(env);
  const { payerAccountId, payerPrivateKey } = resolvePayerCredentials(env);
  const keystore = selectWalletKeyStore({ walletDir: walletPaths.walletDir() });
  await keystore.deleteKey("primary");
  await keystore.deleteKey("holder");
  const rootKeypair = await keystore.ensureKey("primary");
  const holderKeypair = await keystore.ensureKey("holder");
  const rootPublicKeyMultibase = toBase58Multibase(rootKeypair.publicKey);
  const holderPublicKeyMultibase = toBase58Multibase(holderKeypair.publicKey);
  if (!rootPublicKeyMultibase.startsWith("z") || !holderPublicKeyMultibase.startsWith("z")) {
    throw new Error("publicKeyMultibase must start with 'z'.");
  }
  const capabilities = await probeGatewayCapabilities(env.APP_GATEWAY_BASE_URL);
  const maxFeeTinybarsLocal = Number(process.env.USER_PAYS_MAX_FEE_TINYBARS ?? 50_000_000);
  const maxFeeTinybars =
    typeof capabilities?.selfFundedMaxFeeTinybars === "number"
      ? Math.min(maxFeeTinybarsLocal, capabilities.selfFundedMaxFeeTinybars)
      : maxFeeTinybarsLocal;
  const result = await createDidUserPaysViaGateway({
    gatewayBaseUrl: env.APP_GATEWAY_BASE_URL,
    network,
    publicKey: rootKeypair.publicKey,
    publicKeyMultibase: rootPublicKeyMultibase,
    sign: (payload) => keystore.sign("primary", payload),
    payerAccountId,
    payerPrivateKey,
    topicId: env.HEDERA_DID_TOPIC_ID,
    maxFeeTinybars
  });

  console.log("Pending network confirmation...");
  const resolveBaseUrl = env.APP_GATEWAY_BASE_URL ?? env.DID_SERVICE_BASE_URL;
  const resolution = await waitForDidResolution(resolveBaseUrl, result.did);
  console.log(`did_resolution_elapsed_ms=${resolution.elapsedMs} attempts=${resolution.attempts}`);

  // Same holder binding installation as didCreateAuto().
  {
    const providers = {
      clientOptions: {
        network: env.HEDERA_NETWORK,
        accountId: payerAccountId,
        privateKey: payerPrivateKey
      }
    } as RegistrarProviders;
    const holderId = `#holder-${Date.now()}`;
    const updates: Array<Record<string, unknown>> = [
      {
        operation: "add-verification-method",
        id: holderId,
        property: "verificationMethod",
        publicKeyMultibase: holderPublicKeyMultibase
      },
      {
        operation: "add-verification-method",
        id: holderId,
        property: "authentication",
        publicKeyMultibase: holderPublicKeyMultibase
      },
      {
        operation: "add-verification-method",
        id: holderId,
        property: "assertionMethod",
        publicKeyMultibase: holderPublicKeyMultibase
      }
    ];
    const updateReq = await registrarGenerateUpdateRequest({ did: result.did, updates }, providers);
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
    await waitForDidResolution(resolveBaseUrl, result.did, { maxAttempts: 90, intervalMs: 4000 });
  }

  const existing = await loadWalletState();
  const state: WalletState = {
    // Preserve keystore + any future wallet metadata.
    ...(existing ?? {}),
    keys: {
      holder: {
        alg: "Ed25519",
        publicKeyBase64: Buffer.from(holderKeypair.publicKey).toString("base64"),
        publicKeyMultibase: holderPublicKeyMultibase
      }
    },
    credentials: existing?.credentials ?? [],
    did: {
      did: result.did,
      topicId: result.topicId,
      transactionId: result.transactionId
    }
  };

  await saveWalletState(state);
  console.log(`did=${result.did}`);
};

export const didCreate = async () => {
  await didCreateAuto();
};
