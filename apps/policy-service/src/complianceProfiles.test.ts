import { strict as assert } from "node:assert";

// This test is intentionally deterministic/offline:
// it validates profile selection + overlay behavior without DB/network.

process.env.NODE_ENV = "test";
process.env.COMPLIANCE_PROFILE_DEFAULT = "eu";
process.env.COMPLIANCE_PROFILE_ORIGIN_MAP_JSON = JSON.stringify({
  "https://rp.uk.example": "uk",
  "https://rp.eu.example": "eu"
});

const { selectComplianceProfile, applyComplianceProfileOverlay } =
  await import("./complianceProfiles.js");

const baseLogic = {
  binding: { mode: "kb-jwt" as const, require: true },
  requirements: [
    {
      vct: "cuncta.test.vct",
      formats: ["dc+sd-jwt"],
      zk_predicates: [],
      disclosures: [],
      predicates: [],
      context_predicates: [],
      revocation: { required: false }
    }
  ],
  obligations: []
};

{
  const uk = selectComplianceProfile({ verifier_origin: "https://rp.uk.example/path" });
  assert.equal(uk.profile_id, "uk");
  const applied = applyComplianceProfileOverlay({ profile: uk, logic: baseLogic as never });
  assert.equal(applied.logic.requirements[0]?.revocation?.required, true);
}

{
  const eu = selectComplianceProfile({ verifier_origin: "https://rp.eu.example/anything" });
  assert.equal(eu.profile_id, "eu");
  const applied = applyComplianceProfileOverlay({ profile: eu, logic: baseLogic as never });
  // EU profile does not force revocation required (policy-configured).
  assert.equal(applied.logic.requirements[0]?.revocation?.required, false);
}

{
  const fallback = selectComplianceProfile(undefined);
  assert.equal(fallback.profile_id, "eu");
}

console.log("policy-service complianceProfiles: ok");
