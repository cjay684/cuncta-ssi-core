import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { SignJWT, importJWK } from "jose";
import { toBase64Url } from "../encoding/base64url.js";

type WalletState = {
  keys?: {
    ed25519?: {
      privateKeyBase64: string;
      publicKeyBase64: string;
    };
  };
  did?: {
    did?: string;
  };
};

export type PrivacyKbjwtInput = {
  requestId?: string;
  nonce?: string;
  audience?: string;
  output?: (token: string) => void;
};

const walletStatePath = () => {
  const dir = path.dirname(fileURLToPath(import.meta.url));
  return path.join(dir, "..", "..", "wallet-state.json");
};

export const loadWalletState = async (): Promise<WalletState> => {
  const content = await readFile(walletStatePath(), "utf8");
  return JSON.parse(content) as WalletState;
};

export const buildJwk = (privateKeyBase64: string, publicKeyBase64: string) => ({
  kty: "OKP",
  crv: "Ed25519",
  d: toBase64Url(Buffer.from(privateKeyBase64, "base64")),
  x: toBase64Url(Buffer.from(publicKeyBase64, "base64")),
  alg: "EdDSA"
});

const parseOptionalNumber = (value: unknown) => {
  if (value === undefined || value === null || value === "") return undefined;
  const parsed = Number(value);
  return Number.isNaN(parsed) ? undefined : parsed;
};

export const clampTtlSeconds = (value?: number) => {
  const base = Number.isFinite(value as number) ? Number(value) : 120;
  return Math.max(30, Math.min(600, base));
};

export const buildPrivacyKbjwt = async (input: {
  nonce: string;
  audience: string;
  output?: (token: string) => void;
}) => {
  const state = await loadWalletState();
  const key = state.keys?.ed25519;
  if (!key) {
    throw new Error("wallet_state_missing_keys");
  }
  if (!state.did?.did) {
    throw new Error("wallet_state_missing_did");
  }

  const holderJwk = buildJwk(key.privateKeyBase64, key.publicKeyBase64);
  const holderKey = await importJWK(holderJwk as never, "EdDSA");
  const nowSeconds = Math.floor(Date.now() / 1000);
  const envTtl = parseOptionalNumber(process.env.KBJWT_TTL_SECONDS);
  const ttlSeconds = clampTtlSeconds(envTtl);

  const kbJwt = await new SignJWT({
    aud: input.audience,
    nonce: input.nonce,
    iat: nowSeconds,
    exp: nowSeconds + ttlSeconds,
    cnf: { jwk: { kty: "OKP", crv: "Ed25519", x: holderJwk.x, alg: "EdDSA" } }
  })
    .setProtectedHeader({ alg: "EdDSA", typ: "kb+jwt" })
    .sign(holderKey);

  if (input.output) {
    input.output(kbJwt);
  }

  return kbJwt;
};

export const privacyKbjwt = async (input: PrivacyKbjwtInput) => {
  if (!input.requestId || !input.nonce || !input.audience) {
    throw new Error("usage: privacy:kbjwt --requestId <id> --nonce <nonce> --audience <aud>");
  }
  const kbJwt = await buildPrivacyKbjwt({
    nonce: input.nonce,
    audience: input.audience,
    output: input.output
  });
  if (!input.output) {
    console.log(kbJwt);
  }
  return kbJwt;
};
