import { strict as assert } from "node:assert";
import { Oid4vpRequestObjectSchema } from "@cuncta/shared";

const run = async () => {
  // This test is a pure schema/snapshot check; keep it independent from any
  // production-only config requirements (e.g., signing keys).
  const TEST_ENV_OVERRIDES: Record<string, string | undefined> = {
    NODE_ENV: "test",
    HEDERA_NETWORK: "testnet",
    ALLOW_MAINNET: "false",
    ISSUER_SERVICE_BASE_URL: "http://issuer.test",
    POLICY_SERVICE_BASE_URL: "http://policy.test",
    TRUST_PROXY: "false",
    PUBLIC_SERVICE: "false",
    SERVICE_JWT_SECRET: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    SERVICE_JWT_SECRET_VERIFIER: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    // Avoid env-provided production-only config from a developer `.env`.
    ISSUER_JWKS: undefined
  };
  const previousValues = new Map<string, string | undefined>();
  for (const [key, value] of Object.entries(TEST_ENV_OVERRIDES)) {
    previousValues.set(key, process.env[key]);
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }

  const payload = {
    action: "identity.verify",
    challenge: {
      nonce: "nonce-nonce-nonce",
      audience: "origin:http://localhost:3003",
      expires_at: "2026-01-01T00:00:00.000Z"
    },
    requirements: [
      {
        vct: "cuncta.age_over_18",
        formats: ["dc+sd-jwt"],
        zk_predicates: [],
        disclosures: ["seller_good_standing", "tier"],
        predicates: [{ path: "tier", op: "eq", value: "silver" }]
      }
    ]
  };

  try {
    const { __test__ } = await import("./oid4vp.js");
    const requestObj = __test__.buildOid4vpRequestObject(payload as never);
    const validated = Oid4vpRequestObjectSchema.parse(requestObj);

    const snapshot = JSON.stringify(validated);
    assert.equal(
      snapshot,
      JSON.stringify({
        action: "identity.verify",
        nonce: "nonce-nonce-nonce",
        audience: "origin:http://localhost:3003",
        expires_at: "2026-01-01T00:00:00.000Z",
        requirements: [
          {
            vct: "cuncta.age_over_18",
            formats: ["dc+sd-jwt"],
            zk_predicates: [],
            disclosures: ["seller_good_standing", "tier"],
            predicates: [{ path: "tier", op: "eq", value: "silver" }]
          }
        ],
        presentation_definition: {
          id: "cuncta:identity.verify",
          input_descriptors: [
            {
              id: "cuncta.age_over_18",
              format: { "sd-jwt-vc": {} },
              disclosures: ["seller_good_standing", "tier"]
            }
          ]
        }
      })
    );
  } finally {
    for (const [key, value] of previousValues.entries()) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
