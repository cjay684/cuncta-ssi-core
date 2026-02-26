import { createHash, createHmac } from "node:crypto";

export type Pseudonymizer = {
  didToHash: (did: string) => string;
};

export const createSha256Pseudonymizer = (): Pseudonymizer => ({
  didToHash: (did: string) => createHash("sha256").update(did).digest("hex")
});

export const createHmacSha256Pseudonymizer = (input: { pepper: string }): Pseudonymizer => ({
  didToHash: (did: string) =>
    createHmac("sha256", input.pepper).update(did).digest("hex").toLowerCase()
});
