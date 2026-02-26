import { createHash } from "node:crypto";
import { canonicalizeJson } from "./canonicalJson.js";

export const hashCanonicalJson = (value: unknown) =>
  createHash("sha256").update(canonicalizeJson(value)).digest("hex");
