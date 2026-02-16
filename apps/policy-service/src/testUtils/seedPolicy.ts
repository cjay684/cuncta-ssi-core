import { getDb } from "../db.js";

export const ensureMarketplaceListPolicy = async () => {
  const db = await getDb();
  const actionId = "marketplace.list_item";
  const policyId = "marketplace.list_item.v1";

  const now = new Date().toISOString();
  await db("actions")
    .insert({
      action_id: actionId,
      description: "List an item in the marketplace",
      created_at: now,
      updated_at: now
    })
    .onConflict("action_id")
    .merge({ description: "List an item in the marketplace", updated_at: now });

  const logic = {
    binding: { mode: "kb-jwt", require: true },
    requirements: [
      {
        vct: "cuncta.marketplace.seller_good_standing",
        issuer: { mode: "env", env: "ISSUER_DID" },
        disclosures: ["seller_good_standing", "tier"],
        predicates: [
          { path: "seller_good_standing", op: "eq", value: true },
          { path: "domain", op: "eq", value: "marketplace" }
        ],
        revocation: { required: true }
      }
    ]
  };

  await db("policies")
    .insert({
      policy_id: policyId,
      action_id: actionId,
      version: 1,
      enabled: true,
      logic,
      policy_hash: null,
      policy_signature: null,
      created_at: now,
      updated_at: now
    })
    .onConflict("policy_id")
    .merge({
      action_id: actionId,
      version: 1,
      enabled: true,
      logic,
      policy_hash: null,
      policy_signature: null,
      updated_at: now
    });
};
