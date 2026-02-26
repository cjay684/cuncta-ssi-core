import { createHash } from "node:crypto";

export const tokenHashPrefix = (token: string) => {
  const hash = createHash("sha256").update(token).digest("hex");
  return hash.slice(0, 12);
};
