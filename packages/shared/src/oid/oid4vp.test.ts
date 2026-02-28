import { strict as assert } from "node:assert";
import { Oid4vpRequestObjectSchema } from "./oid4vp.js";

const run = async () => {
  const good = {
    action: "identity.verify",
    nonce: "nonce-nonce-nonce",
    audience: "origin:http://localhost:3003",
    expires_at: "2026-01-01T00:00:00.000Z",
    request_jwt:
      "eyJhbGciOiJFZERTQSIsInR5cCI6Im9pZDR2cC1yZXF1ZXN0K2p3dCJ9.eyJpc3MiOiJodHRwOi8vZ2F0ZXdheS5leGFtcGxlIiwibm9uY2UiOiJub25jZS1ub25jZS1ub25jZSIsImF1ZCI6Im9yaWdpbjpodHRwOi8vbG9jYWxob3N0OjMwMDMiLCJleHAiOjE4OTM0NTYwMDB9.signature",
    requirements: [{ vct: "cuncta.age_over_18", disclosures: [] }],
    presentation_definition: { id: "cuncta:identity.verify", input_descriptors: [] }
  };
  Oid4vpRequestObjectSchema.parse(good);

  let rejected = false;
  try {
    Oid4vpRequestObjectSchema.parse({ ...good, nonce: "x" });
  } catch {
    rejected = true;
  }
  assert.equal(rejected, true, "nonce too short should be rejected");

  rejected = false;
  try {
    // strict() should reject unknown top-level fields
    Oid4vpRequestObjectSchema.parse({ ...good, extra: 1 });
  } catch {
    rejected = true;
  }
  assert.equal(rejected, true, "unknown top-level fields should be rejected");
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
