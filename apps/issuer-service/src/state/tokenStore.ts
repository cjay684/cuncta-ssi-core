import { randomUUID } from "node:crypto";

type TokenEntry = {
  expiresAt: number;
};

export class TokenStore {
  private readonly ttlSeconds: number;
  private readonly tokens = new Map<string, TokenEntry>();

  constructor(ttlSeconds: number) {
    this.ttlSeconds = ttlSeconds;
  }

  issue() {
    const token = randomUUID();
    const expiresAt = Date.now() + this.ttlSeconds * 1000;
    this.tokens.set(token, { expiresAt });
    return token;
  }

  isValid(token: string) {
    const entry = this.tokens.get(token);
    if (!entry) {
      return false;
    }
    if (Date.now() > entry.expiresAt) {
      this.tokens.delete(token);
      return false;
    }
    return true;
  }
}
