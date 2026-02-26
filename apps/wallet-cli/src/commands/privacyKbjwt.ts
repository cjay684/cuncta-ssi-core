import { buildHolderJwtEdDsa, ensureHolderPublicJwk } from "../holder/holderKeys.js";
import { loadWalletState } from "../walletStore.js";

type WalletState = {
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
  const state = (await loadWalletState()) as unknown as WalletState;
  const holderPublicJwk = await ensureHolderPublicJwk();
  if (!state.did?.did) {
    throw new Error("wallet_state_missing_did");
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  const envTtl = parseOptionalNumber(process.env.KBJWT_TTL_SECONDS);
  const ttlSeconds = clampTtlSeconds(envTtl);

  const kbJwt = await buildHolderJwtEdDsa({
    header: { alg: "EdDSA", typ: "kb+jwt" },
    payload: {
      aud: input.audience,
      nonce: input.nonce,
      iat: nowSeconds,
      exp: nowSeconds + ttlSeconds,
      cnf: { jwk: { kty: "OKP", crv: "Ed25519", x: holderPublicJwk.x, alg: "EdDSA" } }
    }
  });

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
