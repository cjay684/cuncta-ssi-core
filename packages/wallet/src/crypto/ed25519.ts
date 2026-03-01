import { exportJWK, generateKeyPair, type JWK } from "jose";

export type GeneratedEd25519 = {
  publicJwk: JWK;
  privateJwk: JWK;
  publicKeyBytes: Uint8Array;
  privateKeyBytes: Uint8Array;
};

const toBytes = (value: unknown, name: string) => {
  if (!(value instanceof Uint8Array)) {
    throw new Error(`expected_uint8array:${name}`);
  }
  return value;
};

export const generateEd25519 = async (): Promise<GeneratedEd25519> => {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  const privateJwk = await exportJWK(privateKey);
  // jose uses JsonWebKey; CryptoKey exposes raw via subtle exportKey.
  const publicRaw = await crypto.subtle.exportKey("raw", publicKey);
  const privateRaw = await crypto.subtle.exportKey("pkcs8", privateKey);
  return {
    publicJwk,
    privateJwk,
    publicKeyBytes: toBytes(new Uint8Array(publicRaw), "public"),
    privateKeyBytes: toBytes(new Uint8Array(privateRaw), "private")
  };
};
