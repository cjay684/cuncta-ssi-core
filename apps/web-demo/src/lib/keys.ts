import { base58btc } from "multiformats/bases/base58";
import { toBase64Url } from "./encoding";

export const toBase58Multibase = (bytes: Uint8Array) => base58btc.encode(bytes);

export const buildHolderJwk = (privateKey: Uint8Array, publicKey: Uint8Array) => ({
  kty: "OKP",
  crv: "Ed25519",
  d: toBase64Url(privateKey),
  x: toBase64Url(publicKey),
  alg: "EdDSA"
});
