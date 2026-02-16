import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { z } from "zod";
import { SignJWT, importJWK } from "jose";
import { sha256Base64Url } from "../crypto/sha256.js";
import { toBase64Url } from "../encoding/base64url.js";
import { presentSdJwtVc } from "@cuncta/sdjwt";

const toOptionalNumber = (value: unknown) => {
  if (value === undefined || value === null || value === "") return undefined;
  const parsed = Number(value);
  return Number.isNaN(parsed) ? undefined : parsed;
};

const envSchema = z.object({
  VERIFIER_SERVICE_BASE_URL: z.string().url(),
  ISSUER_SERVICE_BASE_URL: z.string().url(),
  KBJWT_TTL_SECONDS: z.preprocess(toOptionalNumber, z.number().optional())
});

type WalletState = {
  keys?: {
    ed25519?: {
      privateKeyBase64: string;
      publicKeyBase64: string;
    };
  };
  credentials?: Array<{ vct: string; sdJwt: string }>;
};

const walletStatePath = () => {
  const dir = path.dirname(fileURLToPath(import.meta.url));
  return path.join(dir, "..", "..", "wallet-state.json");
};

const loadWalletState = async (): Promise<WalletState> => {
  const content = await readFile(walletStatePath(), "utf8");
  return JSON.parse(content) as WalletState;
};

const buildJwk = (privateKeyBase64: string, publicKeyBase64: string) => ({
  kty: "OKP",
  crv: "Ed25519",
  d: toBase64Url(Buffer.from(privateKeyBase64, "base64")),
  x: toBase64Url(Buffer.from(publicKeyBase64, "base64")),
  alg: "EdDSA"
});

const buildPresentation = async (
  sdJwtPresentation: string,
  audience: string,
  nonce: string,
  holderJwk: Record<string, unknown>,
  ttlSeconds: number
) => {
  const sdHash = sha256Base64Url(sdJwtPresentation);
  const holderKey = await importJWK(holderJwk as never, "EdDSA");
  const nowSeconds = Math.floor(Date.now() / 1000);
  const kbJwt = await new SignJWT({
    aud: audience,
    nonce,
    iat: nowSeconds,
    exp: nowSeconds + ttlSeconds,
    sd_hash: sdHash,
    cnf: { jwk: { kty: "OKP", crv: "Ed25519", x: holderJwk.x, alg: "EdDSA" } }
  })
    .setProtectedHeader({ alg: "EdDSA", typ: "kb+jwt" })
    .sign(holderKey);

  const base = sdJwtPresentation.endsWith("~") ? sdJwtPresentation : `${sdJwtPresentation}~`;
  return `${base}${kbJwt}`;
};

export const presentAge = async () => {
  const env = envSchema.parse(process.env);
  const state = await loadWalletState();
  const key = state.keys?.ed25519;
  if (!key) {
    throw new Error("holder_keys_missing");
  }
  const matching = state.credentials?.filter((cred) => cred.vct === "cuncta.age_over_18") ?? [];
  const credential = matching.at(-1);
  if (!credential) {
    throw new Error("credential_missing");
  }

  const requestUrl = `${env.VERIFIER_SERVICE_BASE_URL}/v1/presentations/request`;
  let reqResponse: Response;
  try {
    reqResponse = await fetch(requestUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        policyId: "dating_age_gate"
      })
    });
  } catch (error) {
    throw new Error(
      `request failed: ${requestUrl} (${error instanceof Error ? error.message : String(error)})`
    );
  }
  if (!reqResponse.ok) {
    const text = await reqResponse.text();
    throw new Error(`request failed: ${text}`);
  }
  const reqPayload = (await reqResponse.json()) as {
    requestId: string;
    nonce: string;
    audience: string;
    requirements?: Array<{
      vct: string;
      predicates?: Array<{ path: string }>;
    }>;
  };

  const catalogUrl = `${env.ISSUER_SERVICE_BASE_URL}/v1/catalog/credentials/cuncta.age_over_18`;
  let catalogResponse: Response;
  try {
    catalogResponse = await fetch(catalogUrl);
  } catch (error) {
    throw new Error(
      `catalog fetch failed: ${catalogUrl} (${error instanceof Error ? error.message : String(error)})`
    );
  }
  if (!catalogResponse.ok) {
    const text = await catalogResponse.text();
    throw new Error(`catalog fetch failed: ${text}`);
  }
  const catalog = (await catalogResponse.json()) as {
    sd_disclosure_defaults?: string[];
    sd_defaults?: string[];
  };
  const defaults = catalog.sd_disclosure_defaults ?? catalog.sd_defaults ?? [];

  const requiredPaths =
    reqPayload.requirements
      ?.filter((req) => req.vct === "cuncta.age_over_18")
      .flatMap((req) => req.predicates?.map((predicate) => predicate.path) ?? []) ?? [];
  const disclosures = requiredPaths.filter((path) => defaults.includes(path));

  const holderJwk = buildJwk(key.privateKeyBase64, key.publicKeyBase64);
  const baseTtl = Number.isFinite(env.KBJWT_TTL_SECONDS as number)
    ? Math.max(30, Math.min(600, Number(env.KBJWT_TTL_SECONDS)))
    : 120;
  const selective = await presentSdJwtVc({ sdJwt: credential.sdJwt, disclose: disclosures });
  const presentation = await buildPresentation(
    selective,
    reqPayload.audience,
    reqPayload.nonce,
    holderJwk,
    baseTtl
  );

  const verifyUrl = `${env.VERIFIER_SERVICE_BASE_URL}/v1/presentations/verify`;
  let verifyResponse: Response;
  try {
    verifyResponse = await fetch(verifyUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        requestId: reqPayload.requestId,
        presentation
      })
    });
  } catch (error) {
    throw new Error(
      `verify failed: ${verifyUrl} (${error instanceof Error ? error.message : String(error)})`
    );
  }
  if (!verifyResponse.ok) {
    const text = await verifyResponse.text();
    throw new Error(`verify failed: ${text}`);
  }
  const verifyPayload = await verifyResponse.json();
  console.log(JSON.stringify(verifyPayload, null, 2));
  return verifyPayload as { valid?: boolean };
};
