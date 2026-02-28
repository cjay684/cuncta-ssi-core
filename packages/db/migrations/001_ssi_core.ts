import { Knex } from "knex";

const toJson = (value: unknown) => JSON.stringify(value);

export async function up(knex: Knex): Promise<void> {
  // ── Credential catalog ──────────────────────────────────────────────
  await knex.schema.createTable("credential_types", (table) => {
    table.text("vct").primary();
    table.jsonb("json_schema").notNullable();
    table.text("schema"); // backward-compat alias used by ZK seed
    table.jsonb("sd_defaults").notNullable();
    table.jsonb("display").notNullable();
    table.jsonb("purpose_limits").notNullable();
    table.jsonb("presentation_templates").notNullable();
    table.jsonb("revocation_config").notNullable();
    table.text("catalog_hash");
    table.text("catalog_signature");
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  // ── Actions ─────────────────────────────────────────────────────────
  await knex.schema.createTable("actions", (table) => {
    table.text("action_id").primary();
    table.text("description").notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  // ── Policies ────────────────────────────────────────────────────────
  await knex.schema.createTable("policies", (table) => {
    table.text("policy_id").primary();
    table
      .text("action_id")
      .notNullable()
      .references("action_id")
      .inTable("actions")
      .onDelete("CASCADE");
    table.integer("version").notNullable();
    table.boolean("enabled").notNullable().defaultTo(true);
    table.jsonb("logic").notNullable();
    table.text("policy_hash");
    table.text("policy_signature");
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  // ── Status lists (revocation) ───────────────────────────────────────
  await knex.schema.createTable("status_lists", (table) => {
    table.text("status_list_id").primary();
    table.text("purpose").notNullable();
    table.integer("bitstring_size").notNullable();
    table.integer("current_version").notNullable().defaultTo(1);
    table.integer("next_index").notNullable().defaultTo(0);
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.createTable("status_list_versions", (table) => {
    table
      .text("status_list_id")
      .notNullable()
      .references("status_list_id")
      .inTable("status_lists")
      .onDelete("CASCADE");
    table.integer("version").notNullable();
    table.text("bitstring_base64").notNullable();
    table.timestamp("published_at", { useTz: true });
    table.text("anchor_payload_hash");
    table.primary(["status_list_id", "version"]);
  });

  // ── Issuance events ─────────────────────────────────────────────────
  await knex.schema.createTable("issuance_events", (table) => {
    table.text("event_id").primary();
    table.text("vct").notNullable();
    table.text("subject_did_hash");
    table.text("credential_fingerprint").notNullable();
    table.text("status_list_id").notNullable();
    table.integer("status_index").notNullable();
    table.timestamp("issued_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.unique(["status_list_id", "status_index"]);
  });

  // ── Anchor outbox ───────────────────────────────────────────────────
  await knex.schema.createTable("anchor_outbox", (table) => {
    table.text("outbox_id").primary();
    table.text("event_type").notNullable();
    table.text("payload_hash").notNullable().unique();
    table.jsonb("payload_meta").notNullable().defaultTo("{}");
    table.text("status").notNullable().defaultTo("PENDING");
    table.integer("attempts").notNullable().defaultTo(0);
    table.timestamp("next_retry_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("processing_started_at", { useTz: true });
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  // ── Anchor receipts ─────────────────────────────────────────────────
  await knex.schema.createTable("anchor_receipts", (table) => {
    table.text("payload_hash").primary();
    table.text("topic_id").notNullable();
    table.text("sequence_number").notNullable();
    table.text("consensus_timestamp").notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  // ── Anchor reconciliations ──────────────────────────────────────────
  await knex.schema.createTable("anchor_reconciliations", (table) => {
    table.uuid("id").primary();
    table.text("payload_hash").notNullable().index();
    table.text("topic_id").notNullable();
    table.bigInteger("sequence_number").notNullable();
    table.text("consensus_timestamp").notNullable();
    table.timestamp("verified_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.text("status").notNullable();
    table.text("reason");
    table.text("mirror_message_hash");
    table.jsonb("mirror_response_meta");
    table.integer("attempts").notNullable().defaultTo(0);
    table.timestamp("last_attempt_at", { useTz: true });
    table.unique(["topic_id", "sequence_number"]);
  });

  // ── Reputation events ───────────────────────────────────────────────
  await knex.schema.createTable("reputation_events", (table) => {
    table.bigIncrements("id").primary();
    table.text("actor_pseudonym").notNullable();
    table.text("counterparty_pseudonym").notNullable();
    table.text("domain").notNullable();
    table.text("event_type").notNullable();
    table.timestamp("timestamp", { useTz: true }).notNullable();
    table.text("evidence_hash");
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  // ── Audit logs ──────────────────────────────────────────────────────
  await knex.schema.createTable("audit_logs", (table) => {
    table.bigIncrements("id").primary();
    table.text("event_type").notNullable();
    table.text("entity_id");
    table.text("data_hash").notNullable();
    table.text("prev_hash");
    table.text("chain_hash");
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  // ── Verification challenges ─────────────────────────────────────────
  await knex.schema.createTable("verification_challenges", (table) => {
    table.text("challenge_id").primary();
    table.text("challenge_hash").notNullable().unique();
    table.text("action_id").notNullable();
    table.timestamp("expires_at", { useTz: true }).notNullable();
    table.timestamp("consumed_at", { useTz: true });
    table.text("audience");
    table.text("policy_id");
    table.integer("policy_version");
    table.text("policy_hash");
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["policy_id", "policy_version"]);
  });

  // ── Rate-limit events ───────────────────────────────────────────────
  await knex.schema.createTable("rate_limit_events", (table) => {
    table.bigIncrements("id").primary();
    table.text("subject_hash").notNullable();
    table.text("action_id").notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["subject_hash", "action_id", "created_at"]);
  });

  // ── Obligation executions ───────────────────────────────────────────
  await knex.schema.createTable("obligations_executions", (table) => {
    table.text("id").primary();
    table.text("action_id").notNullable();
    table.text("policy_id").notNullable();
    table.integer("policy_version").notNullable();
    table.text("decision").notNullable();
    table.text("subject_did_hash").notNullable();
    table.text("token_hash").notNullable();
    table.text("challenge_hash").notNullable();
    table.text("obligations_hash").notNullable();
    table.timestamp("executed_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.text("anchor_payload_hash").notNullable();
    table.text("status").notNullable().defaultTo("PENDING");
    table.text("error_code");
    table.unique(["challenge_hash", "policy_id", "policy_version", "decision", "obligations_hash"]);
    table.unique(["challenge_hash", "action_id", "policy_id", "policy_version", "decision"]);
    table.index(["action_id", "policy_id", "policy_version"]);
  });

  // ── Obligation events ───────────────────────────────────────────────
  await knex.schema.createTable("obligation_events", (table) => {
    table.bigIncrements("id").primary();
    table.text("action_id").notNullable();
    table.text("event_type").notNullable();
    table.text("subject_did_hash").notNullable();
    table.text("token_hash").notNullable();
    table.text("challenge_hash").notNullable();
    table.text("event_hash").notNullable().unique();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["action_id", "subject_did_hash", "created_at"]);
  });

  // ── Privacy / DSR ───────────────────────────────────────────────────
  await knex.schema.createTable("privacy_requests", (table) => {
    table.text("request_id").primary();
    table.text("did_hash").notNullable();
    table.text("nonce_hash").notNullable();
    table.text("audience").notNullable();
    table.timestamp("expires_at", { useTz: true }).notNullable();
    table.timestamp("consumed_at", { useTz: true });
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["did_hash", "created_at"]);
    table.index(["expires_at"]);
  });

  await knex.schema.createTable("privacy_tokens", (table) => {
    table.text("token_hash").primary();
    table.text("did_hash").notNullable();
    table.timestamp("expires_at", { useTz: true }).notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["did_hash", "expires_at"]);
  });

  await knex.schema.createTable("privacy_restrictions", (table) => {
    table.text("did_hash").primary();
    table.timestamp("restricted_at", { useTz: true }).notNullable();
    table.text("reason_hash");
    table.index(["restricted_at"]);
  });

  await knex.schema.createTable("privacy_tombstones", (table) => {
    table.text("did_hash").primary();
    table.timestamp("erased_at", { useTz: true }).notNullable();
    table.index(["erased_at"]);
  });

  // ── System metadata ─────────────────────────────────────────────────
  await knex.schema.createTable("system_metadata", (table) => {
    table.text("key").primary();
    table.text("value").notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  // ── Issuer keys ─────────────────────────────────────────────────────
  await knex.schema.createTable("issuer_keys", (table) => {
    table.text("kid").primary();
    table.jsonb("public_jwk").notNullable();
    table.jsonb("private_jwk");
    table.text("status").notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["status"]);
  });

  // ── Policy version floor ────────────────────────────────────────────
  await knex.schema.createTable("policy_version_floor", (table) => {
    table.text("action_id").primary();
    table.integer("min_version").notNullable();
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  // ── OID4VCI: pre-authorized codes ──────────────────────────────────
  await knex.schema.createTable("oid4vci_preauth_codes", (table) => {
    table.text("code_hash").primary();
    table.text("vct").notNullable();
    table.text("tx_code_hash");
    table.jsonb("scope_json");
    table.text("scope_hash");
    table.timestamp("expires_at", { useTz: true }).notNullable();
    table.timestamp("consumed_at", { useTz: true });
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["expires_at"]);
    table.index(["consumed_at"]);
    table.index(["vct", "created_at"]);
    table.index(["scope_hash"], "oid4vci_preauth_scope_hash_idx");
  });

  // ── OID4VCI: c_nonce replay prevention ─────────────────────────────
  await knex.schema.createTable("oid4vci_c_nonces", (table) => {
    table.text("nonce_hash").primary();
    table.text("token_jti_hash").notNullable();
    table.timestamp("expires_at", { useTz: true }).notNullable();
    table.timestamp("consumed_at", { useTz: true });
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["expires_at"]);
    table.index(["consumed_at"]);
    table.index(["token_jti_hash", "created_at"]);
  });

  // ── OID4VP: request-object one-time semantics ──────────────────────
  await knex.schema.createTable("oid4vp_request_hashes", (table) => {
    table.text("request_hash").primary();
    table.timestamp("expires_at", { useTz: true }).notNullable();
    table.timestamp("consumed_at", { useTz: true });
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["expires_at"]);
    table.index(["consumed_at"]);
  });

  // ── OID4VCI: offer challenges ──────────────────────────────────────
  await knex.schema.createTable("oid4vci_offer_challenges", (table) => {
    table.text("nonce_hash").primary();
    table.timestamp("expires_at", { useTz: true }).notNullable();
    table.timestamp("consumed_at", { useTz: true });
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["expires_at"]);
    table.index(["consumed_at"]);
  });

  // ── ZK age groups ──────────────────────────────────────────────────
  await knex.schema.createTable("zk_age_groups", (table) => {
    table.text("group_id").primary();
    table.integer("merkle_depth").notNullable();
    table.text("root").notNullable();
    table.integer("member_count").notNullable().defaultTo(0);
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.createTable("zk_age_group_members", (table) => {
    table.text("member_id").primary();
    table.text("group_id").notNullable().index();
    table.text("identity_commitment").notNullable().index();
    table.text("subject_did_hash").notNullable().index();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.unique(["group_id", "identity_commitment"]);
  });

  // ── Seed: credential types ─────────────────────────────────────────
  await knex("credential_types").insert([
    {
      vct: "cuncta.age_over_18",
      json_schema: toJson({
        type: "object",
        properties: { age_over_18: { type: "boolean" } },
        required: ["age_over_18"],
        additionalProperties: false,
      }),
      sd_defaults: toJson(["age_over_18"]),
      display: toJson({
        title: "Age 18+",
        claims: [{ path: "age_over_18", label: "Over 18" }],
      }),
      purpose_limits: toJson({ actions: ["dating_age_gate", "dating_enter"] }),
      presentation_templates: toJson({ required_disclosures: ["age_over_18"] }),
      revocation_config: toJson({
        statusPurpose: "revocation",
        statusListId: "default",
        bitstringSize: 2048,
      }),
    },
    {
      vct: "age_credential_v1",
      json_schema: toJson({
        type: "object",
        properties: {
          dob_commitment: { type: "string" },
          commitment_scheme_version: { type: "string" },
        },
        required: ["dob_commitment", "commitment_scheme_version"],
        additionalProperties: false,
      }),
      sd_defaults: toJson(["dob_commitment", "commitment_scheme_version"]),
      display: toJson({ title: "Age credential (ZK-ready)" }),
      purpose_limits: toJson({ actions: ["dating_enter", "dating_age_gate"] }),
      presentation_templates: toJson({
        required_disclosures: ["dob_commitment", "commitment_scheme_version"],
      }),
      revocation_config: toJson({
        statusPurpose: "revocation",
        statusListId: "default",
        bitstringSize: 2048,
      }),
    },
    {
      vct: "cuncta.zk.age.v1",
      json_schema: toJson({
        type: "object",
        properties: {
          predicate: { type: "string" },
          groupId: { type: "string" },
          merkleDepth: { type: "number" },
          identityCommitment: { type: "string" },
        },
        required: ["predicate", "groupId", "merkleDepth", "identityCommitment"],
      }),
      schema: toJson({
        type: "object",
        properties: {
          predicate: { type: "string" },
          groupId: { type: "string" },
          merkleDepth: { type: "number" },
          identityCommitment: { type: "string" },
        },
        required: ["predicate", "groupId", "merkleDepth", "identityCommitment"],
      }),
      sd_defaults: toJson([]),
      display: toJson({ name: "Age predicate credential (ZK)" }),
      purpose_limits: toJson({}),
      presentation_templates: toJson({}),
      revocation_config: toJson({
        statusPurpose: "revocation",
        statusListId: "default",
        bitstringSize: 2048,
      }),
    },
  ]);

  // ── Seed: test action + policy ─────────────────────────────────────
  await knex("actions").insert({
    action_id: "identity.verify",
    description: "Verify a holder identity credential",
  });

  await knex("policies").insert({
    policy_id: "identity.verify.v1",
    action_id: "identity.verify",
    version: 1,
    enabled: true,
    logic: toJson({
      binding: { mode: "kb-jwt", require: true },
      requirements: [
        {
          vct: "cuncta.age_over_18",
          issuer: { mode: "env", env: "ISSUER_DID" },
          formats: ["dc+sd-jwt"],
          disclosures: ["age_over_18"],
          predicates: [{ path: "age_over_18", op: "eq", value: true }],
          revocation: { required: true },
        },
      ],
      obligations: [
        { type: "ANCHOR_EVENT", event: "VERIFY", when: "ON_ALLOW" },
      ],
    }),
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists("zk_age_group_members");
  await knex.schema.dropTableIfExists("zk_age_groups");
  await knex.schema.dropTableIfExists("oid4vci_offer_challenges");
  await knex.schema.dropTableIfExists("oid4vp_request_hashes");
  await knex.schema.dropTableIfExists("oid4vci_c_nonces");
  await knex.schema.dropTableIfExists("oid4vci_preauth_codes");
  await knex.schema.dropTableIfExists("policy_version_floor");
  await knex.schema.dropTableIfExists("issuer_keys");
  await knex.schema.dropTableIfExists("system_metadata");
  await knex.schema.dropTableIfExists("privacy_tombstones");
  await knex.schema.dropTableIfExists("privacy_restrictions");
  await knex.schema.dropTableIfExists("privacy_tokens");
  await knex.schema.dropTableIfExists("privacy_requests");
  await knex.schema.dropTableIfExists("obligation_events");
  await knex.schema.dropTableIfExists("obligations_executions");
  await knex.schema.dropTableIfExists("rate_limit_events");
  await knex.schema.dropTableIfExists("verification_challenges");
  await knex.schema.dropTableIfExists("audit_logs");
  await knex.schema.dropTableIfExists("reputation_events");
  await knex.schema.dropTableIfExists("anchor_reconciliations");
  await knex.schema.dropTableIfExists("anchor_receipts");
  await knex.schema.dropTableIfExists("anchor_outbox");
  await knex.schema.dropTableIfExists("issuance_events");
  await knex.schema.dropTableIfExists("status_list_versions");
  await knex.schema.dropTableIfExists("status_lists");
  await knex.schema.dropTableIfExists("policies");
  await knex.schema.dropTableIfExists("actions");
  await knex.schema.dropTableIfExists("credential_types");
}
