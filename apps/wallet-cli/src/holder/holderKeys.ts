import { selectWalletKeyStore } from "@cuncta/wallet-keystore";
import { walletPaths, loadWalletState } from "../walletStore.js";
import { toBase64Url } from "../encoding/base64url.js";

type HolderKeyState = {
  alg: "Ed25519";
  publicKeyBase64: string;
  publicKeyMultibase: string;
};

const base64url = (input: Uint8Array | string) =>
  Buffer.from(typeof input === "string" ? input : input).toString("base64url");

export const resolveHolderKeyState = async (): Promise<HolderKeyState> => {
  const state = await loadWalletState();
  const key = (state as any)?.keys?.holder as HolderKeyState | undefined;
  if (key?.alg === "Ed25519" && key.publicKeyBase64 && key.publicKeyMultibase) {
    return key;
  }
  // Backward compat: existing wallets may still have `keys.ed25519` populated.
  const legacy = (state as any)?.keys?.ed25519 as
    | { publicKeyBase64?: string; publicKeyMultibase?: string; privateKeyBase64?: string }
    | undefined;
  if (legacy?.publicKeyBase64 && legacy.publicKeyMultibase) {
    return { alg: "Ed25519", publicKeyBase64: legacy.publicKeyBase64, publicKeyMultibase: legacy.publicKeyMultibase };
  }
  throw new Error("holder_keys_missing");
};

export const getHolderKeyStore = () => {
  return selectWalletKeyStore({ walletDir: walletPaths.walletDir() });
};

export const ensureHolderPublicJwk = async () => {
  const keyState = await resolveHolderKeyState();
  if (keyState.alg !== "Ed25519") {
    throw new Error("holder_alg_unsupported");
  }
  const publicKeyBytes = Buffer.from(keyState.publicKeyBase64, "base64");
  return {
    kty: "OKP",
    crv: "Ed25519",
    x: toBase64Url(publicKeyBytes),
    alg: "EdDSA"
  };
};

export const signWithHolderKey = async (bytes: Uint8Array) => {
  const keystore = getHolderKeyStore();
  return await keystore.sign("holder", bytes);
};

export const buildHolderJwtEdDsa = async (input: {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
}) => {
  const headerB64 = base64url(JSON.stringify(input.header));
  const payloadB64 = base64url(JSON.stringify(input.payload));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = await signWithHolderKey(Buffer.from(signingInput, "utf8"));
  const signatureB64 = base64url(signature);
  return `${signingInput}.${signatureB64}`;
};

