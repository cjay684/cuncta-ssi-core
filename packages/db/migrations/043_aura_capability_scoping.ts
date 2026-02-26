import { Knex } from "knex";

const parseJson = (value: unknown): Record<string, unknown> => {
  if (!value) return {};
  if (typeof value === "string") {
    try {
      return JSON.parse(value) as Record<string, unknown>;
    } catch {
      return {};
    }
  }
  if (typeof value === "object") return value as Record<string, unknown>;
  return {};
};

export async function up(knex: Knex): Promise<void> {
  // 1) Replace unsafe wildcard domains with a scoped prefix pattern.
  // "*" is effectively cross-domain and risks "global scoring". Use "space:*" for per-space capabilities.
  await knex("aura_rules").where({ domain: "*" }).update({ domain: "space:*", updated_at: new Date().toISOString() });

  // 2) Ensure every rule has a human-readable purpose text (capability framing).
  // Purpose is stored inside rule_logic so it is integrity-protected by the existing rule signature scheme.
  const rows = (await knex("aura_rules").select(
    "rule_id",
    "domain",
    "output_vct",
    "rule_logic",
    "enabled",
    "rule_signature"
  )) as Array<{
    rule_id: string;
    domain: string;
    output_vct: string;
    rule_logic: unknown;
    enabled: boolean;
    rule_signature?: string | null;
  }>;

  for (const row of rows) {
    const logic = parseJson(row.rule_logic);
    const existingPurpose = typeof logic.purpose === "string" ? logic.purpose.trim() : "";
    if (existingPurpose) continue;

    // Best-effort default: capability text is explicit and domain-scoped.
    logic.purpose = `Capability for ${row.output_vct} within domain ${row.domain}`;

    // IMPORTANT: changing rule_logic invalidates existing signatures; clear so bootstrap can re-sign.
    await knex("aura_rules")
      .where({ rule_id: row.rule_id })
      .update({
        rule_logic: JSON.stringify(logic),
        rule_signature: null,
        updated_at: new Date().toISOString()
      });
  }
}

export async function down(knex: Knex): Promise<void> {
  // Non-destructive: do not attempt to remove `purpose` from rule_logic.
  // Reverting domain pattern also risks reintroducing unsafe wildcard behavior.
  await knex("aura_rules").where({ domain: "space:*" }).update({ domain: "*", updated_at: new Date().toISOString() });
}

