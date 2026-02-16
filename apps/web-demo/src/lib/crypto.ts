import { fromBase64Url, toBase64Url } from "./encoding";

export const sha256Base64Url = async (value: string) => {
  const data = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return toBase64Url(new Uint8Array(digest));
};

export const sha256Hex = async (value: string) => {
  const data = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
};

export const decodeDisclosure = (disclosure: string) => {
  const decoded = fromBase64Url(disclosure);
  const text = new TextDecoder().decode(decoded);
  return JSON.parse(text) as unknown[];
};
