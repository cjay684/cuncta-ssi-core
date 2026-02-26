import { strict as assert } from "node:assert";
import { checkIssuerRule } from "./issuerTrust.js";

{
  const ok = await checkIssuerRule({
    issuerDid: "did:example:any",
    rule: { mode: "allowlist", allowed: ["*"] }
  });
  assert.equal(ok.ok, true);
}

{
  const denied = await checkIssuerRule({
    issuerDid: "did:example:any",
    rule: { mode: "allowlist", allowed: ["did:example:other"] }
  });
  assert.deepEqual(denied, { ok: false, reason: "issuer_not_allowed" });
}

{
  process.env.TEST_ISSUER_DID = "did:example:env";
  const ok = await checkIssuerRule({
    issuerDid: "did:example:env",
    rule: { mode: "env", env: "TEST_ISSUER_DID" }
  });
  assert.equal(ok.ok, true);
}

{
  const ok = await checkIssuerRule({
    issuerDid: "did:example:issuer",
    rule: { mode: "trust_registry", registry_id: "default", trust_mark: "accredited" }
  });
  assert.equal(ok.ok, true);
}

{
  const denied = await checkIssuerRule({
    issuerDid: "did:example:unknown",
    rule: { mode: "trust_registry", registry_id: "default", trust_mark: "accredited" }
  });
  assert.deepEqual(denied, { ok: false, reason: "issuer_not_trusted" });
}

console.log("verifier-service issuerTrust: ok");

