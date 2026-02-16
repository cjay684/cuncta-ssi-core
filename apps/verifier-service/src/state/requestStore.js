import { randomBytes, randomUUID } from "node:crypto";
export class PresentationRequestStore {
  ttlMs;
  entries = new Map();
  constructor(ttlMs) {
    this.ttlMs = ttlMs;
  }
  create(input) {
    const now = new Date();
    const requestId = randomUUID();
    const expiresAt = new Date(now.getTime() + this.ttlMs).toISOString();
    const entry = {
      ...input,
      requestId,
      issuedAt: now.toISOString(),
      expiresAt
    };
    this.entries.set(requestId, entry);
    return entry;
  }
  get(requestId) {
    const entry = this.entries.get(requestId);
    if (!entry) {
      return null;
    }
    if (Date.now() > Date.parse(entry.expiresAt)) {
      this.entries.delete(requestId);
      return null;
    }
    return entry;
  }
}
export const createNonce = (size = 24) => randomBytes(size).toString("base64url");
//# sourceMappingURL=requestStore.js.map
