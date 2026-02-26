import { getDb } from "../db.js";
import { writeAuditLog } from "../audit.js";
import { hashCanonicalJson } from "@cuncta/shared";
import { processAuraSignalsOnce } from "../aura/auraWorker.js";
import { getDidHashes } from "../pseudonymizer.js";

export type ReputationEventInput = {
  actor_pseudonym: string;
  counterparty_pseudonym: string;
  domain: string;
  event_type: string;
  timestamp: string;
  evidence_hash?: string;
};

export const recordEvent = async (input: ReputationEventInput) => {
  const db = await getDb();
  const actorHash = getDidHashes(input.actor_pseudonym).primary;
  const counterpartyHash = getDidHashes(input.counterparty_pseudonym).primary;
  const eventHash = hashCanonicalJson({
    subjectDidHash: actorHash,
    counterpartyDidHash: counterpartyHash,
    domain: input.domain,
    signal: input.event_type,
    weight: 1,
    occurredAt: input.timestamp,
    evidenceHash: input.evidence_hash ?? null
  });
  await db("aura_signals")
    .insert({
      subject_did_hash: actorHash,
      counterparty_did_hash: counterpartyHash,
      domain: input.domain,
      signal: input.event_type,
      weight: 1,
      event_hash: eventHash,
      created_at: input.timestamp
    })
    .onConflict("event_hash")
    .ignore();
  await writeAuditLog("reputation_event_recorded", {
    entityId: actorHash,
    domain: input.domain,
    eventType: input.event_type,
    counterpartyHash
  });
};

export const recomputeReputation = async (actorDid: string) => {
  const db = await getDb();
  const hashes = getDidHashes(actorDid);
  const actorHash = hashes.primary;
  await processAuraSignalsOnce();
  const lookup = hashes.legacy ? [hashes.primary, hashes.legacy] : [hashes.primary];
  const states = await db("aura_state").whereIn("subject_did_hash", lookup);
  await writeAuditLog("reputation_recomputed", {
    entityId: actorHash,
    domainCount: states.length
  });

  return {
    subjectDidHash: actorHash,
    domains: states.map((row) => ({
      domain: row.domain,
      state: row.state
    }))
  };
};
