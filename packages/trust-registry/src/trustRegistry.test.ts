import { strict as assert } from "node:assert";
import { isTrustedIssuer, loadTrustRegistry } from "./loader.js";

const run = async () => {
  const registry = await loadTrustRegistry();
  assert.ok(registry.registry_id.length > 0);
  assert.ok(Array.isArray(registry.issuers));

  const trusted = await isTrustedIssuer({ issuerDid: "did:example:issuer", requireMark: "accredited" });
  assert.equal(trusted.trusted, true);

  const untrusted = await isTrustedIssuer({ issuerDid: "did:example:unknown", requireMark: "accredited" });
  assert.equal(untrusted.trusted, false);

  console.log("trust-registry: ok");
};

await run();

