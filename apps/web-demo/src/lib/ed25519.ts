import { getPublicKeyAsync, hashes, signAsync } from "@noble/ed25519";

if (!hashes.sha512Async) {
  hashes.sha512Async = async (message: Uint8Array) => {
    const digest = await crypto.subtle.digest("SHA-512", message as BufferSource);
    return new Uint8Array(digest);
  };
}

export const generateKeypair = async () => {
  const privateKey = crypto.getRandomValues(new Uint8Array(32));
  const publicKey = await getPublicKeyAsync(privateKey);
  return { privateKey, publicKey };
};

export const signPayload = async (payload: Uint8Array, privateKey: Uint8Array) => {
  return signAsync(payload, privateKey);
};
