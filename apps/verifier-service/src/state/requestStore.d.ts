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
    revocation?: {
      required: boolean;
    };
  }[];
};
export declare class PresentationRequestStore {
  private readonly ttlMs;
  private readonly entries;
  constructor(ttlMs: number);
  create(
    input: Omit<PresentationRequestEntry, "requestId" | "issuedAt" | "expiresAt">
  ): PresentationRequestEntry;
  get(requestId: string): PresentationRequestEntry | null;
}
export declare const createNonce: (size?: number) => string;
