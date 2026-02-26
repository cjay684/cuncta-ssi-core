import { createHash, randomBytes } from "node:crypto";
import { getPublicKey, hashes, sign } from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";

if (!hashes.sha512) {
  hashes.sha512 = sha512;
}

export type KeyPair = {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
};

export const generateKeypair = async (): Promise<KeyPair> => {
  const privateKey = randomBytes(32);
  const publicKey = await getPublicKey(privateKey);
  return { privateKey, publicKey };
};

export const signPayload = async (payload: Uint8Array, privateKey: Uint8Array) =>
  sign(payload, privateKey);

export const sha256Hex = (data: Uint8Array | string) =>
  createHash("sha256").update(data).digest("hex");
