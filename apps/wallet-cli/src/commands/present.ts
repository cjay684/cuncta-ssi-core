import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { z } from "zod";
import { SignJWT, importJWK } from "jose";
import { presentSdJwtVc } from "@cuncta/sdjwt";
import { sha256Base64Url } from "../crypto/sha256.js";
import { toBase64Url } from "../encoding/base64url.js";

const toOptionalNumber = (value: unknown) => {
  if (value === undefined || value === null || value === "") return undefined;
  const parsed = Number(value);
  return Number.isNaN(parsed) ? undefined : parsed;
};

const envSchema = z.object({
  POLICY_SERVICE_BASE_URL: z.string().url(),
  KBJWT_TTL_SECONDS: z.preprocess(toOptionalNumber, z.number().optional())
});

type WalletState = {
  keys?: {
    ed25519?: {
      privateKeyBase64: string;
      publicKeyBase64: string;
    };
  };
  credentials?: Array<{
    vct: string;
    credential?: string;
    sdJwt?: string;
    eventId: string;
    credentialFingerprint: string;
  }>;
  lastPresentation?: {
    action: string;
    presentation: string;
    nonce: string;
    audience: string;
  };
};

const walletStatePath = () => {
  const dir = path.dirname(fileURLToPath(import.meta.url));
  return path.join(dir, "..", "..", "wallet-state.json");
};

const loadWalletState = async (): Promise<WalletState> => {
  const content = await readFile(walletStatePath(), "utf8");
  return JSON.parse(content) as WalletState;
};

const saveWalletState = async (state: WalletState) => {
  await writeFile(walletStatePath(), JSON.stringify(state, null, 2), "utf8");
};

const buildJwk = (privateKeyBase64: string, publicKeyBase64: string) => ({
  kty: "OKP",
  crv: "Ed25519",
  d: toBase64Url(Buffer.from(privateKeyBase64, "base64")),
  x: toBase64Url(Buffer.from(publicKeyBase64, "base64")),
  alg: "EdDSA"
});

export const present = async (action = "marketplace.list_item") => {
  const env = envSchema.parse(process.env);
  const state = await loadWalletState();
  const key = state.keys?.ed25519;
  if (!key) {
    throw new Error("holder_keys_missing");
  }

  const requirementsUrl = `${env.POLICY_SERVICE_BASE_URL}/v1/requirements?action=${encodeURIComponent(
    action
  )}`;
  const response = await fetch(requirementsUrl);
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`requirements_failed: ${text}`);
  }
  const payload = (await response.json()) as {
    action: string;
    challenge: { nonce: string; audience: string; expires_at: string };
    requirements: Array<{ vct: string; disclosures: string[] }>;
  };

  const requirement = payload.requirements[0];
  if (!requirement) {
    throw new Error("requirements_missing");
  }
  const credential = state.credentials?.find((cred) => cred.vct === requirement.vct);
  if (!credential) {
    throw new Error("credential_missing");
  }

  const sdJwtPresentation = await presentSdJwtVc({
    sdJwt: credential.credential ?? (credential as unknown as { sdJwt?: string }).sdJwt ?? "",
    disclose: requirement.disclosures
  });

  const holderJwk = buildJwk(key.privateKeyBase64, key.publicKeyBase64);
  const nowSeconds = Math.floor(Date.now() / 1000);
  const secondsUntilExpiry = Math.max(
    0,
    Math.floor((Date.parse(payload.challenge.expires_at) - Date.now()) / 1000)
  );
  const baseTtl = Number.isFinite(env.KBJWT_TTL_SECONDS as number)
    ? Math.max(30, Math.min(600, Number(env.KBJWT_TTL_SECONDS)))
    : 120;
  const ttlSeconds = Math.max(1, Math.min(baseTtl, secondsUntilExpiry));
  const holderKey = await importJWK(holderJwk as never, "EdDSA");
  const kbJwt = await new SignJWT({
    aud: payload.challenge.audience,
    nonce: payload.challenge.nonce,
    iat: nowSeconds,
    exp: nowSeconds + ttlSeconds,
    sd_hash: sha256Base64Url(sdJwtPresentation),
    cnf: { jwk: { kty: "OKP", crv: "Ed25519", x: holderJwk.x, alg: "EdDSA" } }
  })
    .setProtectedHeader({ alg: "EdDSA", typ: "kb+jwt" })
    .sign(holderKey);

  const presentation = `${sdJwtPresentation}${kbJwt}`;
  state.lastPresentation = {
    action,
    presentation,
    nonce: payload.challenge.nonce,
    audience: payload.challenge.audience
  };
  await saveWalletState(state);
  console.log(JSON.stringify(state.lastPresentation, null, 2));
};
