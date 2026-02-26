import { strict as assert } from "node:assert";
import { __test__ } from "./present.js";

const b64u = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");

const makeJwt = (payload: Record<string, unknown>) => {
  // This is NOT a valid signature; we only use it to exercise strict preflight checks
  // that happen before JWKS fetch / cryptographic verification.
  const header = { alg: "none", typ: "oid4vp-request+jwt" };
  return `${b64u(header)}.${b64u(payload)}.signature`;
};

const run = async () => {
  // Missing iss: strict mode must fail closed.
  {
    const jwt = makeJwt({ nonce: "n" });
    try {
      __test__.resolveRequestJwtJwksUrl(jwt, { strict: true });
      assert.fail("Expected request_jwt_issuer_missing");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      assert.equal(msg, "request_jwt_issuer_missing");
    }
    const url = __test__.resolveRequestJwtJwksUrl(jwt, { strict: false });
    assert.equal(url, "");
  }

  // Invalid iss: strict mode must fail closed.
  {
    const jwt = makeJwt({ iss: "not-a-url", nonce: "n" });
    try {
      __test__.resolveRequestJwtJwksUrl(jwt, { strict: true });
      assert.fail("Expected request_jwt_issuer_invalid");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      assert.equal(msg, "request_jwt_issuer_invalid");
    }
    const url = __test__.resolveRequestJwtJwksUrl(jwt, { strict: false });
    assert.equal(url, "");
  }

  console.log("present.requestSignature.test: all assertions passed");
};

run().catch((err) => {
  console.error(err);
  process.exit(1);
});

