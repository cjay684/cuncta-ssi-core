import { randomBytes, randomUUID } from "node:crypto";

export type PresentationRequestEntry = {
  requestId: string;
  nonce: string;
  audience: string;
  policyId: string;
  issuedAt: string;
  expiresAt: string;
  requirements: {
    vct: string;
    disclosures: string[];
    predicates: {
      path: string;
      op: "eq" | "neq" | "gte" | "lte" | "in" | "exists";
      value?: unknown;
    }[];
    revocation?: { required: boolean };
  }[];
};

export class PresentationRequestStore {
  private readonly ttlMs: number;
  private readonly entries = new Map<string, PresentationRequestEntry>();

  constructor(ttlMs: number) {
    this.ttlMs = ttlMs;
  }

  create(input: Omit<PresentationRequestEntry, "requestId" | "issuedAt" | "expiresAt">) {
    const now = new Date();
    const requestId = randomUUID();
    const expiresAt = new Date(now.getTime() + this.ttlMs).toISOString();
    const entry: PresentationRequestEntry = {
      ...input,
      requestId,
      issuedAt: now.toISOString(),
      expiresAt
    };
    this.entries.set(requestId, entry);
    return entry;
  }

  get(requestId: string) {
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
