import {
  SignJWT,
  exportJWK,
  generateKeyPair,
  importJWK,
  createRemoteJWKSet,
  createLocalJWKSet,
  jwtVerify
} from "jose";
import type { JWK } from "jose";
import { config } from "../config.js";

let cachedJwks: { keys: JWK[] } | null = null;
let cachedPrivateKey: CryptoKey | null = null;
let cachedKid: string | null = null;

const getSigningKey = async (): Promise<{ key: CryptoKey; kid: string }> => {
  if (cachedPrivateKey && cachedKid) {
    return { key: cachedPrivateKey, kid: cachedKid };
  }
  if (config.OID4VCI_TOKEN_SIGNING_JWK) {
    let jwk: JWK;
    try {
      jwk = JSON.parse(config.OID4VCI_TOKEN_SIGNING_JWK) as JWK;
    } catch {
      throw new Error("oid4vci_token_signing_jwk_invalid");
    }
    if (!jwk.kid) {
      jwk.kid = "oid4vci-token-1";
    }
    const key = await importJWK(jwk, "EdDSA");
    if (!key || !(key instanceof CryptoKey)) {
      throw new Error("oid4vci_token_signing_jwk_import_failed");
    }
    cachedPrivateKey = key;
    cachedKid = jwk.kid;
    return { key, kid: jwk.kid };
  }
  if (config.OID4VCI_TOKEN_SIGNING_BOOTSTRAP) {
    const { privateKey, publicKey } = await generateKeyPair("EdDSA", {
      crv: "Ed25519",
      extractable: true
    });
    const jwk = await exportJWK(publicKey);
    jwk.kid = "oid4vci-token-bootstrap";
    jwk.alg = "EdDSA";
    jwk.use = "sig";
    cachedPrivateKey = privateKey;
    cachedKid = jwk.kid;
    return { key: privateKey, kid: jwk.kid };
  }
  throw new Error("oid4vci_token_signing_key_missing");
};

export type SignOid4vciTokenInput = {
  issuer: string;
  audience: string;
  ttlSeconds: number;
  scope: string[];
  // Bind this access token to a specific credential configuration id (preauth offer).
  // Prevents a redeemed preauth code from being used to mint a different credential configuration.
  credentialConfigurationId?: string | null;
  // Optional minimal context for the issuance (hash-only/TTL in DB; mirrored here for enforcement).
  context?: Record<string, unknown> | null;
};

export const signOid4vciAccessToken = async (input: SignOid4vciTokenInput): Promise<string> => {
  const { key, kid } = await getSigningKey();
  const now = Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = { scope: input.scope };
  if (input.credentialConfigurationId) {
    payload.vct = input.credentialConfigurationId;
  }
  if (input.context && typeof input.context === "object") {
    payload.ctx = input.context;
  }
  return await new SignJWT(payload)
    .setProtectedHeader({ alg: "EdDSA", typ: "at+jwt", kid })
    .setIssuer(input.issuer)
    .setAudience(input.audience)
    .setIssuedAt(now)
    .setExpirationTime(now + input.ttlSeconds)
    .setJti(crypto.randomUUID())
    .sign(key);
};

export const getOid4vciTokenJwks = async (): Promise<{ keys: JWK[] }> => {
  if (cachedJwks) {
    return cachedJwks;
  }
  const { key, kid } = await getSigningKey();
  const jwk = await exportJWK(key);
  const publicJwk = { ...jwk } as Record<string, unknown>;
  delete publicJwk.d;
  publicJwk.kid = kid ?? (jwk as JWK).kid;
  publicJwk.alg = "EdDSA";
  publicJwk.use = "sig";
  cachedJwks = { keys: [publicJwk as JWK] };
  return cachedJwks;
};

const toScopeList = (value: unknown): string[] => {
  if (Array.isArray(value)) {
    return value.map((v) => String(v)).filter((v) => v.trim().length > 0);
  }
  if (typeof value === "string") {
    return value
      .split(" ")
      .map((v) => v.trim())
      .filter((v) => v.length > 0);
  }
  return [];
};

export type VerifyOid4vciAccessTokenEdDSAInput = {
  token: string;
  issuerBaseUrl: string;
  requiredScopes: string[];
  jwks?: { keys: JWK[] };
};

export const verifyOid4vciAccessTokenEdDSA = async (
  input: VerifyOid4vciAccessTokenEdDSAInput
): Promise<{ payload: Record<string, unknown>; scope: string[] }> => {
  const JWKS = input.jwks
    ? createLocalJWKSet(input.jwks)
    : createRemoteJWKSet(new URL(`${input.issuerBaseUrl.replace(/\/$/, "")}/jwks.json`));
  const verified = await jwtVerify(input.token, JWKS, {
    algorithms: ["EdDSA"],
    typ: "at+jwt",
    issuer: input.issuerBaseUrl,
    audience: input.issuerBaseUrl
  });
  const scope = toScopeList((verified.payload as Record<string, unknown>).scope);
  for (const required of input.requiredScopes) {
    if (!scope.includes(required)) {
      throw new Error("oid4vci_token_missing_required_scope");
    }
  }
  return { payload: verified.payload as Record<string, unknown>, scope };
};
