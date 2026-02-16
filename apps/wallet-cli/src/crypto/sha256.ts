import { createHash } from "node:crypto";

export const sha256Base64Url = (data: Uint8Array | string) =>
  createHash("sha256").update(data).digest("base64url");
