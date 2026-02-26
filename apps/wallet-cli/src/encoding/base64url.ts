export const toBase64Url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

export const fromBase64Url = (value: string) => new Uint8Array(Buffer.from(value, "base64url"));
