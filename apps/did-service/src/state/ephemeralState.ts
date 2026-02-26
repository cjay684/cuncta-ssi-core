import { randomUUID } from "node:crypto";

export type DidCreateOptions = {
  topicManagement: "shared" | "single";
  includeServiceEndpoints: boolean;
};

export type HederaNetwork = "testnet" | "previewnet" | "mainnet";

export type SigningStateEntry = {
  publicKeyMultibase: string;
  network: HederaNetwork;
  payloadToSign: Uint8Array;
  operationState: unknown;
  options: DidCreateOptions;
  createdAt: string;
  expiresAt: string;
};

export class EphemeralStateStore {
  private readonly ttlMs: number;
  private readonly entries = new Map<string, SigningStateEntry>();

  constructor(ttlMs: number) {
    this.ttlMs = ttlMs;
  }

  create(entry: Omit<SigningStateEntry, "createdAt" | "expiresAt">) {
    const createdAt = new Date();
    const expiresAt = new Date(createdAt.getTime() + this.ttlMs);
    const state = randomUUID();
    const value: SigningStateEntry = {
      ...entry,
      createdAt: createdAt.toISOString(),
      expiresAt: expiresAt.toISOString()
    };
    this.entries.set(state, value);
    return { state, entry: value };
  }

  get(state: string) {
    const entry = this.entries.get(state);
    if (!entry) {
      return null;
    }
    if (Date.now() > Date.parse(entry.expiresAt)) {
      this.entries.delete(state);
      return null;
    }
    return entry;
  }

  consume(state: string) {
    const entry = this.get(state);
    if (!entry) {
      return null;
    }
    this.entries.delete(state);
    return entry;
  }
}
