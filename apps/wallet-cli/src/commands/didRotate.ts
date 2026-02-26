import { z } from "zod";
import * as Registrar from "@hiero-did-sdk/registrar";
import { toBase58Multibase } from "../encoding/multibase.js";
import { generateKeypair } from "../crypto/ed25519.js";
import { loadWalletState, saveWalletState } from "../walletStore.js";
import { selectWalletKeyStore } from "@cuncta/wallet-keystore";
import { walletPaths } from "../walletStore.js";
import { base58btc } from "multiformats/bases/base58";

const HederaNetwork = z.enum(["testnet", "previewnet", "mainnet"]);

const envSchema = z
  .object({
    NODE_ENV: z.string().optional(),
    DID_SERVICE_BASE_URL: z.string().url(),
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
  const fn = (registrar as unknown as { generateUpdateDIDRequest?: (a: unknown, b: unknown) => Promise<unknown> })
    .generateUpdateDIDRequest;
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
  const fn = (registrar as unknown as { submitUpdateDIDRequest?: (a: unknown, b: unknown) => Promise<unknown> })
    .submitUpdateDIDRequest;
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

export const didRotate = async () => {
  const commandStarted = Date.now();
  process.stdout.write("stage=did.rotate|event=start|elapsedMs=0\n");
  const heartbeat = setInterval(() => {
    console.log(`stage=did.rotate|event=heartbeat|elapsedMs=${Date.now() - commandStarted}`);
  }, 5000);
  heartbeat.unref?.();

  try {
    const env = envSchema.parse(process.env);
    const state = await loadWalletState();
    const did = state.did?.did;
    if (!did) throw new Error("holder_did_missing");
    const keystore = selectWalletKeyStore({ walletDir: walletPaths.walletDir() });

    const toFragmentId = (value: string) => {
    const hashIndex = value.indexOf("#");
    if (hashIndex !== -1) {
      return `#${value.slice(hashIndex + 1)}`;
    }
    return value.startsWith("#") ? value : `#${value}`;
  };

    const decodeMethodKeyBytes = (method: Record<string, unknown>): Uint8Array | null => {
    const mb = method.publicKeyMultibase;
    if (typeof mb === "string" && mb.length > 3) {
      try {
        let bytes = base58btc.decode(mb);
        // Some DID docs encode Ed25519 keys as multibase(multicodec(pubkey)): 0xed01 + 32 bytes.
        if (bytes.length === 34 && bytes[0] === 0xed && bytes[1] === 0x01) {
          bytes = bytes.slice(2);
        }
        if (bytes.length === 32) return bytes;
      } catch {
        // ignore invalid multibase
      }
    }
    const jwk = method.publicKeyJwk;
    if (jwk && typeof jwk === "object") {
      const x = (jwk as Record<string, unknown>).x;
      if (typeof x === "string" && x.length > 10) {
        try {
          const bytes = new Uint8Array(Buffer.from(x, "base64url"));
          if (bytes.length === 32) return bytes;
        } catch {
          // ignore invalid base64url
        }
      }
    }
    return null;
  };

    const resolved = await fetch(
      new URL(`/v1/dids/resolve/${encodeURIComponent(did)}`, env.DID_SERVICE_BASE_URL),
      { method: "GET" }
    );
    if (!resolved.ok) {
      throw new Error("did_resolve_failed");
    }
    const payload = (await resolved.json()) as { didDocument?: Record<string, unknown> };
    const methods = Array.isArray(payload.didDocument?.verificationMethod)
      ? (payload.didDocument?.verificationMethod as Array<Record<string, unknown>>)
      : [];
    const holderPubB64 = String((state as any)?.keys?.holder?.publicKeyBase64 ?? "");
    const holderBytes = holderPubB64 ? Buffer.from(holderPubB64, "base64") : Buffer.alloc(0);
    const matching = holderBytes.length
      ? methods.find((m) => {
          const bytes = decodeMethodKeyBytes(m);
          return Boolean(bytes && bytes.length === holderBytes.length && Buffer.from(bytes).equals(holderBytes));
        })
      : undefined;
    const firstMethodId = methods.length && typeof methods[0]?.id === "string" ? (methods[0].id as string) : "";
    const removeIdRaw = typeof (matching as any)?.id === "string" ? String((matching as any).id) : firstMethodId;
    const removeId = removeIdRaw ? toFragmentId(removeIdRaw) : "";

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
    // The registrar expects `publicKeyMultibase` when the fragment doesn't exist yet (even for auth/assertion refs).
    { operation: "add-verification-method", id: nextId, property: "authentication", publicKeyMultibase: nextPublicKeyMultibase },
    { operation: "add-verification-method", id: nextId, property: "assertionMethod", publicKeyMultibase: nextPublicKeyMultibase }
  ];
    if (removeId) {
      updates.push({ operation: "remove-verification-method", id: removeId });
    }

    const { payerAccountId, payerPrivateKey } = resolvePayer(env);
    const providers = {
      clientOptions: { network: env.HEDERA_NETWORK, accountId: payerAccountId, privateKey: payerPrivateKey }
    } as RegistrarProviders;

    const updateReq = await registrarGenerateUpdateRequest({ did, updates }, providers);
    const signingRequests = (updateReq?.signingRequests ?? {}) as Record<string, { serializedPayload?: Uint8Array }>;
    const signatures: Record<string, Uint8Array> = {};
    for (const [key, req] of Object.entries(signingRequests)) {
      const payloadToSign = (req.serializedPayload ?? new Uint8Array()) as Uint8Array;
      // DID updates are authorized by the DID root key (primary).
      signatures[key] = await keystore.sign("primary", payloadToSign);
    }
    await registrarSubmitUpdateRequest(
      { states: updateReq.states, signatures, waitForDIDVisibility: false, visibilityTimeoutMs: 120_000 },
      providers
    );
    if (typeof keystore.saveKeyMaterial !== "function") {
      throw new Error("keystore_rotation_not_supported");
    }
    await keystore.saveKeyMaterial({
      // Rotate the holder binding key (kb-jwt), not the DID root key.
      purpose: "holder",
      alg: "Ed25519",
      privateKey: nextKeypair.privateKey,
      publicKey: nextKeypair.publicKey,
      publicKeyMultibase: nextPublicKeyMultibase
    });
    // Reload state to preserve keystore updates written by saveKeyMaterial().
    const refreshed = await loadWalletState();
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
    } as any;
    await saveWalletState(nextState);
    console.log(JSON.stringify({ ok: true, did, rotated: true, removed: removeId || null }, null, 2));
  } finally {
    clearInterval(heartbeat);
  }
};

