type QuotaEntry = {
  timestamps: number[];
};

export class QuotaStore {
  private readonly store = new Map<string, QuotaEntry>();

  consume(key: string, limit: number, windowMs: number): boolean {
    const now = Date.now();
    const entry = this.store.get(key) ?? { timestamps: [] };
    const cutoff = now - windowMs;
    entry.timestamps = entry.timestamps.filter((value) => value >= cutoff);
    if (entry.timestamps.length >= limit) {
      this.store.set(key, entry);
      return false;
    }
    entry.timestamps.push(now);
    this.store.set(key, entry);
    return true;
  }
}
