import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { z } from "zod";
import { randomUUID } from "node:crypto";
import * as Registrar from "@hiero-did-sdk/registrar";
import { DIDOwnerMessage } from "@hiero-did-sdk/messages";
import { OnboardingStrategy, parseOnboardingStrategyList } from "@cuncta/shared";
import {
  AccountId,
  Client,
  Hbar,
  PrivateKey,
  PublicKey,
  TopicMessageSubmitTransaction,
  TransactionId
} from "@hashgraph/sdk";
import { fromBase64Url, toBase64Url } from "../encoding/base64url.js";
import { toBase58Multibase } from "../encoding/multibase.js";
import { generateKeypair, sha256Hex, signPayload } from "../crypto/ed25519.js";

const envSchema = z.object({
  NODE_ENV: z.string().optional(),
  DID_SERVICE_BASE_URL: z.string().url(),
  APP_GATEWAY_BASE_URL: z.string().url().optional(),
  HEDERA_NETWORK: z.literal("testnet").optional(),
  HEDERA_DID_TOPIC_ID: z.string().optional(),
  HEDERA_PAYER_ACCOUNT_ID: z.string().optional(),
  HEDERA_PAYER_PRIVATE_KEY: z.string().optional(),
  HEDERA_OPERATOR_ID: z.string().optional(),
  HEDERA_OPERATOR_PRIVATE_KEY: z.string().optional(),
  ONBOARDING_STRATEGY_DEFAULT: z.string().optional(),
  ONBOARDING_STRATEGY_ALLOWED: z.string().optional()
});

type WalletState = {
  keys: {
    ed25519: {
      privateKeyBase64: string;
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

const walletStatePath = () => {
  const dir = path.dirname(fileURLToPath(import.meta.url));
  return path.join(dir, "..", "..", "wallet-state.json");
};

const saveWalletState = async (state: WalletState) => {
  await writeFile(walletStatePath(), JSON.stringify(state, null, 2), "utf8");
};

const loadWalletState = async (): Promise<WalletState | null> => {
  try {
    const content = await readFile(walletStatePath(), "utf8");
    return JSON.parse(content) as WalletState;
  } catch {
    return null;
  }
};

const requestSchema = z.object({
  state: z.string().uuid(),
  signingRequest: z.object({
    publicKeyMultibase: z.string(),
    alg: z.literal("EdDSA"),
    payloadToSignB64u: z.string(),
    createdAt: z.string()
  })
});

const submitSchema = z.object({
  did: z.string(),
  didDocument: z.unknown().optional(),
  visibility: z.enum(["pending", "confirmed"]).optional(),
  hedera: z.object({
    topicId: z.string(),
    transactionId: z.string(),
    consensusTimestamp: z.string().optional()
  })
});

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
    try {
      const response = await fetch(
        new URL(`/v1/dids/resolve/${encodeURIComponent(did)}`, didServiceBaseUrl)
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
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new Error(`Timed out waiting for DID resolution: ${did}`);
};

const createDidViaGateway = async (input: {
  gatewayBaseUrl: string;
  network: "testnet";
  publicKeyMultibase: string;
  privateKey: Uint8Array;
}) => {
  const deviceId = randomUUID();
  const requestResponse = await fetch(
    new URL("/v1/onboard/did/create/request", input.gatewayBaseUrl),
    {
      method: "POST",
      headers: { "content-type": "application/json", "x-device-id": deviceId },
      body: JSON.stringify({
        network: input.network,
        publicKeyMultibase: input.publicKeyMultibase,
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
    if (payload?.error === "sponsored_onboarding_disabled") {
      const err = new Error("sponsored_onboarding_disabled");
      (err as { code?: string }).code = "sponsored_onboarding_disabled";
      throw err;
    }
    throw new Error(`gateway create request failed: ${payload?.message ?? bodyText}`);
  }
  const requestPayload = requestSchema.parse(await requestResponse.json());
  if (requestPayload.signingRequest.publicKeyMultibase !== input.publicKeyMultibase) {
    throw new Error("publicKeyMultibase mismatch in signing request.");
  }
  const payloadToSign = fromBase64Url(requestPayload.signingRequest.payloadToSignB64u);
  const signature = await signPayload(payloadToSign, input.privateKey);
  console.log(`payloadSha256=${sha256Hex(payloadToSign)}`);
  console.log(`signatureSha256=${sha256Hex(signature)}`);
  const submitResponse = await fetch(
    new URL("/v1/onboard/did/create/submit", input.gatewayBaseUrl),
    {
      method: "POST",
      headers: { "content-type": "application/json", "x-device-id": deviceId },
      body: JSON.stringify({
        state: requestPayload.state,
        signatureB64u: toBase64Url(signature),
        waitForVisibility: false
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
    if (payload?.error === "sponsored_onboarding_disabled") {
      const err = new Error("sponsored_onboarding_disabled");
      (err as { code?: string }).code = "sponsored_onboarding_disabled";
      throw err;
    }
    throw new Error(`gateway create submit failed: ${payload?.message ?? bodyText}`);
  }
  const submitPayload = submitSchema.parse(await submitResponse.json());
  return {
    did: submitPayload.did,
    topicId: submitPayload.hedera.topicId,
    transactionId: submitPayload.hedera.transactionId
  };
};

const createDidUserPaysViaGateway = async (input: {
  gatewayBaseUrl: string;
  network: "testnet";
  publicKey: Uint8Array;
  publicKeyMultibase: string;
  privateKey: Uint8Array;
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
  const message = new DIDOwnerMessage({
    publicKey,
    network: requestPayload.network,
    topicId: requestPayload.topicId
  });
  const signature = await signPayload(message.messageBytes, input.privateKey);
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
  network: "testnet";
  payerAccountId: string;
  payerPrivateKey: string;
  publicKeyMultibase: string;
  privateKey: Uint8Array;
  didServiceBaseUrl: string;
  topicId?: string;
}) => {
  const providers = {
    clientOptions: {
      network: "testnet" as unknown as string,
      accountId: input.payerAccountId,
      privateKey: input.payerPrivateKey
    }
  } as RegistrarProviders;
  const createResult = await registrar.generateCreateDIDRequest(
    {
      multibasePublicKey: input.publicKeyMultibase,
      topicId: input.topicId
    },
    providers
  );
  const payloadToSign = createResult.signingRequest.serializedPayload;
  const signature = await signPayload(payloadToSign, input.privateKey);
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
  const network = env.HEDERA_NETWORK ?? "testnet";
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

const resolvePayerCredentials = (env: z.infer<typeof envSchema>) => {
  const payerAccountId = env.HEDERA_PAYER_ACCOUNT_ID?.trim();
  const payerPrivateKey = env.HEDERA_PAYER_PRIVATE_KEY?.trim();
  if (payerAccountId && payerPrivateKey) {
    return { payerAccountId, payerPrivateKey, usedFallback: false };
  }
  const nodeEnv = env.NODE_ENV ?? process.env.NODE_ENV ?? "development";
  const network = env.HEDERA_NETWORK ?? "testnet";
  if (nodeEnv === "production" || network !== "testnet") {
    throw new Error(
      "Missing HEDERA_PAYER_ACCOUNT_ID or HEDERA_PAYER_PRIVATE_KEY (required outside testnet/dev)"
    );
  }
  const operatorAccountId = env.HEDERA_OPERATOR_ID?.trim();
  const operatorPrivateKey = env.HEDERA_OPERATOR_PRIVATE_KEY?.trim();
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
      selfFundedOnboarding?: { enabled?: boolean };
      network?: string;
    };
    if (!payload || typeof payload !== "object") return null;
    return {
      selfFundedOnboardingEnabled: Boolean(payload.selfFundedOnboarding?.enabled),
      network: typeof payload.network === "string" ? payload.network : undefined
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
};

export const didCreateAuto = async (modeOverride?: OnboardingStrategy) => {
  const env = envSchema.parse(process.env);
  const network = env.HEDERA_NETWORK ?? "testnet";
  const serviceBaseUrl = env.DID_SERVICE_BASE_URL;
  const gatewayBaseUrl = env.APP_GATEWAY_BASE_URL ?? "http://localhost:3010";
  const defaultStrategy: OnboardingStrategy =
    env.ONBOARDING_STRATEGY_DEFAULT === "user_pays" ? "user_pays" : "sponsored";
  const strategy = resolveStrategy({
    allowed: env.ONBOARDING_STRATEGY_ALLOWED,
    requested: modeOverride,
    fallback: defaultStrategy
  });

  const keypair = await generateKeypair();
  const publicKeyMultibase = toBase58Multibase(keypair.publicKey);
  if (!publicKeyMultibase.startsWith("z")) {
    throw new Error("publicKeyMultibase must start with 'z'.");
  }

  console.log(`network=${network}`);
  console.log(`onboarding_mode=${strategy}`);

  let result: { did: string; topicId: string; transactionId: string };
  if (strategy === "sponsored") {
    try {
      result = await createDidViaGateway({
        gatewayBaseUrl,
        network,
        publicKeyMultibase,
        privateKey: keypair.privateKey
      });
    } catch (error) {
      const code = error instanceof Error ? (error as { code?: string }).code : undefined;
      if (code === "sponsored_onboarding_disabled") {
        assertNoOperatorFallbackInProd(env);
        const { payerAccountId, payerPrivateKey } = resolvePayerCredentials(env);
        console.warn("Sponsored onboarding disabled; falling back to user-pays.");
        const maxFeeTinybars = Number(process.env.USER_PAYS_MAX_FEE_TINYBARS ?? 50_000_000);
        if (env.APP_GATEWAY_BASE_URL) {
          const capabilities = await probeGatewayCapabilities(gatewayBaseUrl);
          const canUseGateway =
            capabilities?.selfFundedOnboardingEnabled && capabilities?.network === network;
          try {
            if (!canUseGateway) {
              throw new Error("gateway_user_pays_unavailable");
            }
            result = await createDidUserPaysViaGateway({
              gatewayBaseUrl,
              network,
              publicKey: keypair.publicKey,
              publicKeyMultibase,
              privateKey: keypair.privateKey,
              payerAccountId,
              payerPrivateKey,
              topicId: env.HEDERA_DID_TOPIC_ID,
              maxFeeTinybars
            });
          } catch (gatewayError) {
            const gatewayCode =
              gatewayError instanceof Error ? (gatewayError as { code?: string }).code : undefined;
            if (gatewayCode !== "self_funded_onboarding_disabled") {
              if ((gatewayError as Error).message !== "gateway_user_pays_unavailable") {
                throw gatewayError;
              }
            }
            result = await createDidUserPays({
              network,
              payerAccountId,
              payerPrivateKey,
              publicKeyMultibase,
              privateKey: keypair.privateKey,
              didServiceBaseUrl: serviceBaseUrl,
              topicId: env.HEDERA_DID_TOPIC_ID
            });
          }
        } else {
          result = await createDidUserPays({
            network,
            payerAccountId,
            payerPrivateKey,
            publicKeyMultibase,
            privateKey: keypair.privateKey,
            didServiceBaseUrl: serviceBaseUrl,
            topicId: env.HEDERA_DID_TOPIC_ID
          });
        }
      } else {
        throw error;
      }
    }
  } else {
    assertNoOperatorFallbackInProd(env);
    const { payerAccountId, payerPrivateKey } = resolvePayerCredentials(env);
    const maxFeeTinybars = Number(process.env.USER_PAYS_MAX_FEE_TINYBARS ?? 50_000_000);
    if (env.APP_GATEWAY_BASE_URL) {
      const capabilities = await probeGatewayCapabilities(gatewayBaseUrl);
      const canUseGateway =
        capabilities?.selfFundedOnboardingEnabled && capabilities?.network === network;
      try {
        if (!canUseGateway) {
          throw new Error("gateway_user_pays_unavailable");
        }
        result = await createDidUserPaysViaGateway({
          gatewayBaseUrl,
          network,
          publicKey: keypair.publicKey,
          publicKeyMultibase,
          privateKey: keypair.privateKey,
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
          publicKeyMultibase,
          privateKey: keypair.privateKey,
          didServiceBaseUrl: serviceBaseUrl,
          topicId: env.HEDERA_DID_TOPIC_ID
        });
      }
    } else {
      result = await createDidUserPays({
        network,
        payerAccountId,
        payerPrivateKey,
        publicKeyMultibase,
        privateKey: keypair.privateKey,
        didServiceBaseUrl: serviceBaseUrl,
        topicId: env.HEDERA_DID_TOPIC_ID
      });
    }
  }

  console.log("Pending network confirmation...");
  const resolveBaseUrl = env.APP_GATEWAY_BASE_URL ?? serviceBaseUrl;
  const resolution = await waitForDidResolution(resolveBaseUrl, result.did);
  console.log(`did_resolution_elapsed_ms=${resolution.elapsedMs} attempts=${resolution.attempts}`);

  const existing = await loadWalletState();
  const state: WalletState = {
    keys: {
      ed25519: {
        privateKeyBase64: Buffer.from(keypair.privateKey).toString("base64"),
        publicKeyBase64: Buffer.from(keypair.publicKey).toString("base64"),
        publicKeyMultibase
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

export const didCreateUserPays = async () => {
  await didCreateAuto("user_pays");
};

export const didCreateUserPaysGateway = async () => {
  const env = envSchema.parse(process.env);
  const network = env.HEDERA_NETWORK ?? "testnet";
  if (!env.APP_GATEWAY_BASE_URL) {
    throw new Error("APP_GATEWAY_BASE_URL is required for gateway user-pays");
  }
  console.log(`network=${network}`);
  assertNoOperatorFallbackInProd(env);
  const { payerAccountId, payerPrivateKey } = resolvePayerCredentials(env);
  const keypair = await generateKeypair();
  const publicKeyMultibase = toBase58Multibase(keypair.publicKey);
  if (!publicKeyMultibase.startsWith("z")) {
    throw new Error("publicKeyMultibase must start with 'z'.");
  }
  const maxFeeTinybars = Number(process.env.USER_PAYS_MAX_FEE_TINYBARS ?? 50_000_000);
  const result = await createDidUserPaysViaGateway({
    gatewayBaseUrl: env.APP_GATEWAY_BASE_URL,
    network,
    publicKey: keypair.publicKey,
    publicKeyMultibase,
    privateKey: keypair.privateKey,
    payerAccountId,
    payerPrivateKey,
    topicId: env.HEDERA_DID_TOPIC_ID,
    maxFeeTinybars
  });

  console.log("Pending network confirmation...");
  const resolveBaseUrl = env.APP_GATEWAY_BASE_URL ?? env.DID_SERVICE_BASE_URL;
  const resolution = await waitForDidResolution(resolveBaseUrl, result.did);
  console.log(`did_resolution_elapsed_ms=${resolution.elapsedMs} attempts=${resolution.attempts}`);

  const existing = await loadWalletState();
  const state: WalletState = {
    keys: {
      ed25519: {
        privateKeyBase64: Buffer.from(keypair.privateKey).toString("base64"),
        publicKeyBase64: Buffer.from(keypair.publicKey).toString("base64"),
        publicKeyMultibase
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
