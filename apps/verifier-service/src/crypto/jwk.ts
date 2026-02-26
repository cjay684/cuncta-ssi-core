type JwkRecord = Record<string, unknown>;

const base64UrlPattern = /^[A-Za-z0-9_-]+$/;

export const decodeBase64UrlStrict = (value: string) => {
  if (!value || !base64UrlPattern.test(value) || value.length % 4 === 1) {
    throw new Error("jwk_base64url_invalid");
  }
  try {
    return Buffer.from(value, "base64url");
  } catch {
    throw new Error("jwk_base64url_invalid");
  }
};

export const assertEd25519Jwk = (input: JwkRecord, label: string) => {
  const kty = input.kty;
  const crv = input.crv;
  const alg = input.alg;
  const x = input.x;
  if (kty !== "OKP" || crv !== "Ed25519") {
    throw new Error(`${label}_jwk_invalid`);
  }
  if (alg !== undefined && alg !== "EdDSA") {
    throw new Error(`${label}_jwk_invalid`);
  }
  if (typeof x !== "string") {
    throw new Error(`${label}_jwk_invalid`);
  }
  decodeBase64UrlStrict(x);
  return input as JwkRecord & { kty: "OKP"; crv: "Ed25519"; x: string; alg?: "EdDSA" };
};
