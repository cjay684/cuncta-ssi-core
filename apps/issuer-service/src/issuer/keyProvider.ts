import { JWK } from "jose";
import { bootstrapIssuerDid } from "./bootstrapIssuerDid.js";

export type KeyProvider = {
  getIssuerJwk(): Promise<JWK>;
};

const toBase64UrlFromBase64 = (value: string) => Buffer.from(value, "base64").toString("base64url");

export class DevFileKeyProvider implements KeyProvider {
  async getIssuerJwk(): Promise<JWK> {
    const issuerIdentity = await bootstrapIssuerDid();
    const { privateKeyBase64, publicKeyBase64 } = issuerIdentity.keys.ed25519;
    return {
      kty: "OKP",
      crv: "Ed25519",
      x: toBase64UrlFromBase64(publicKeyBase64),
      d: toBase64UrlFromBase64(privateKeyBase64),
      alg: "EdDSA",
      kid: "issuer-1"
    };
  }
}

export class EnvJwkKeyProvider implements KeyProvider {
  constructor(private readonly jwkJson: string) {}

  async getIssuerJwk(): Promise<JWK> {
    let parsed: JWK;
    try {
      parsed = JSON.parse(this.jwkJson) as JWK;
    } catch {
      throw new Error("issuer_jwk_invalid");
    }
    if (!parsed.kid) {
      parsed.kid = "issuer-1";
    }
    return parsed;
  }
}

export class KmsKeyProvider implements KeyProvider {
  async getIssuerJwk(): Promise<JWK> {
    throw new Error("kms_key_provider_not_implemented");
  }
}
