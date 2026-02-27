import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  // Cleanup: disable duplicate enabled rules (keep highest version) so the invariant can be enforced.
  const enabled = (await knex("aura_rules")
    .where({ enabled: true })
    .select("rule_id", "domain", "output_vct", "version", "updated_at")) as Array<{
    rule_id: string;
    domain: string;
    output_vct: string;
    version: number;
    updated_at: string;
  }>;
  const groups = new Map<string, typeof enabled>();
  for (const row of enabled) {
    const key = `${row.domain}::${row.output_vct}`;
    const list = groups.get(key) ?? [];
    list.push(row);
    groups.set(key, list);
  }
  for (const list of groups.values()) {
    if (list.length <= 1) continue;
    const sorted = [...list].sort((a, b) => {
      if (a.version !== b.version) return b.version - a.version;
      return String(b.updated_at).localeCompare(String(a.updated_at));
    });
    const keep = sorted[0]!;
    const disable = sorted.slice(1).map((r) => r.rule_id);
    await knex("aura_rules")
      .whereIn("rule_id", disable)
      .update({ enabled: false, updated_at: new Date().toISOString() });
    console.log(
      `[aura_rules] disabled_duplicate_rules domain=${keep.domain} output_vct=${keep.output_vct} disabled=${disable.length}`
    );
  }

  // At most one enabled rule per (domain_pattern, output_vct).
  // This prevents ambiguous capability derivation and "silent scoring changes".
  await knex.raw(`
    CREATE UNIQUE INDEX IF NOT EXISTS aura_rules_one_enabled_per_domain_output_idx
    ON aura_rules(domain, output_vct)
    WHERE enabled = true
  `);
}

export async function down(knex: Knex): Promise<void> {
  await knex.raw(`DROP INDEX IF EXISTS aura_rules_one_enabled_per_domain_output_idx`);
}
