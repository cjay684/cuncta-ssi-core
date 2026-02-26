import { z } from "zod";
import * as Registrar from "@hiero-did-sdk/registrar";
import { loadWalletState } from "../walletStore.js";
import { selectWalletKeyStore } from "@cuncta/wallet-keystore";
import { walletPaths } from "../walletStore.js";

const HederaNetwork = z.enum(["testnet", "previewnet", "mainnet"]);

const envSchema = z
  .object({
    NODE_ENV: z.string().optional(),
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

type RegistrarDeactivateRequest = { state: unknown; signingRequest: { serializedPayload: Uint8Array } };

const registrarGenerateDeactivateRequest = async (
  did: string,
  providers: RegistrarProviders
): Promise<RegistrarDeactivateRequest> => {
  const fn = (registrar as unknown as { generateDeactivateDIDRequest?: (a: unknown, b: unknown) => Promise<unknown> })
    .generateDeactivateDIDRequest;
  if (!fn) throw new Error("did_deactivate_not_supported");
  const res = (await fn({ did }, providers)) as unknown as RegistrarDeactivateRequest;
  return res;
};

const registrarSubmitDeactivateRequest = async (
  input: {
    state: unknown;
    signature: Uint8Array;
    waitForDIDVisibility: boolean;
    visibilityTimeoutMs: number;
  },
  providers: RegistrarProviders
): Promise<{ did?: unknown }> => {
  const fn = (registrar as unknown as { submitDeactivateDIDRequest?: (a: unknown, b: unknown) => Promise<unknown> })
    .submitDeactivateDIDRequest;
  if (!fn) throw new Error("did_deactivate_not_supported");
  return (await fn(input, providers)) as { did?: unknown };
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

export const didDeactivate = async () => {
  const env = envSchema.parse(process.env);
  const state = await loadWalletState();
  const did = state.did?.did;
  if (!did) throw new Error("holder_did_missing");
  const keystore = selectWalletKeyStore({ walletDir: walletPaths.walletDir() });

  const { payerAccountId, payerPrivateKey } = resolvePayer(env);
  const providers = {
    clientOptions: { network: env.HEDERA_NETWORK, accountId: payerAccountId, privateKey: payerPrivateKey }
  } as RegistrarProviders;

  const req = await registrarGenerateDeactivateRequest(did, providers);
  const payloadToSign = req.signingRequest.serializedPayload;
  const signature = await keystore.sign("primary", payloadToSign);
  const result = await registrarSubmitDeactivateRequest(
    { state: req.state, signature, waitForDIDVisibility: false, visibilityTimeoutMs: 120_000 },
    providers
  );
  console.log(JSON.stringify({ ok: true, did: String(result?.did ?? did), deactivated: true }, null, 2));
};

