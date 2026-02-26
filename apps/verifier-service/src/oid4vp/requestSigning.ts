import { SignJWT, exportJWK, generateKeyPair, importJWK, createRemoteJWKSet, jwtVerify } from "jose";
import type { JWK } from "jose";
import { config } from "../config.js";

export type SignRequestInput = {
  nonce: string;
  audience: string;
  exp: number;
  action_id: string;
  policyHash: string;
  iss: string;
  state?: string;
  response_uri?: string;
  response_mode?: string;
  response_type?: string;
  client_id?: string;
  client_id_scheme?: string;
  presentation_definition?: Record<string, unknown>;
  zk_context?: Record<string, unknown>;
};

let cachedJwks: { keys: JWK[] } | null = null;
let cachedPrivateKey: CryptoKey | null = null;
let cachedKid: string | null = null;

const getSigningKey = async (): Promise<{ key: CryptoKey; kid: string }> => {
  if (cachedPrivateKey && cachedKid) {
    return { key: cachedPrivateKey, kid: cachedKid };
  }
  if (config.VERIFIER_SIGNING_JWK) {
    let jwk: JWK;
    try {
      jwk = JSON.parse(config.VERIFIER_SIGNING_JWK) as JWK;
    } catch {
      throw new Error("verifier_signing_jwk_invalid");
    }
    if (!jwk.kid) {
      jwk.kid = "verifier-oid4vp-1";
    }
    const key = await importJWK(jwk, "EdDSA");
    if (!key || !(key instanceof CryptoKey)) {
      throw new Error("verifier_signing_jwk_import_failed");
    }
    cachedPrivateKey = key;
    cachedKid = jwk.kid;
    return { key, kid: jwk.kid };
  }
  if (config.VERIFIER_SIGNING_BOOTSTRAP) {
    const { privateKey, publicKey } = await generateKeyPair("EdDSA", {
      crv: "Ed25519",
      extractable: true
    });
    const jwk = await exportJWK(publicKey);
    jwk.kid = "verifier-oid4vp-bootstrap";
    jwk.alg = "EdDSA";
    jwk.use = "sig";
    cachedPrivateKey = privateKey;
    cachedKid = jwk.kid;
    return { key: privateKey, kid: jwk.kid };
  }
  throw new Error("verifier_signing_key_missing");
};

export const signOid4vpRequest = async (input: SignRequestInput): Promise<string> => {
  const { key, kid } = await getSigningKey();
  return await new SignJWT({
    nonce: input.nonce,
    audience: input.audience,
    action_id: input.action_id,
    policy_hash: input.policyHash,
    ...(input.state ? { state: input.state } : {}),
    ...(input.response_uri ? { response_uri: input.response_uri } : {}),
    ...(input.response_mode ? { response_mode: input.response_mode } : {}),
    ...(input.response_type ? { response_type: input.response_type } : {}),
    ...(input.client_id ? { client_id: input.client_id } : {}),
    ...(input.client_id_scheme ? { client_id_scheme: input.client_id_scheme } : {}),
    ...(input.presentation_definition ? { presentation_definition: input.presentation_definition } : {}),
    ...(input.zk_context ? { zk_context: input.zk_context } : {})
  })
    .setProtectedHeader({ alg: "EdDSA", typ: "oid4vp-request+jwt", kid })
    .setIssuer(input.iss)
    .setIssuedAt(Math.floor(Date.now() / 1000))
    .setExpirationTime(input.exp)
    .sign(key);
};

export const getVerifierJwks = async (): Promise<{ keys: JWK[] }> => {
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

export const verifyOid4vpRequestJwt = async (
  jwt: string,
  jwksUrl: string
): Promise<{ nonce: string; audience: string; action_id: string; policy_hash: string; exp: number }> => {
  const JWKS = createRemoteJWKSet(new URL(jwksUrl));
  const { payload } = await jwtVerify(jwt, JWKS, {
    algorithms: ["EdDSA"],
    typ: "oid4vp-request+jwt"
  });
  const p = payload as Record<string, unknown>;
  return {
    nonce: String(p.nonce ?? ""),
    audience: String(p.audience ?? ""),
    action_id: String(p.action_id ?? ""),
    policy_hash: String(p.policy_hash ?? ""),
    exp: Number(p.exp ?? 0)
  };
};
