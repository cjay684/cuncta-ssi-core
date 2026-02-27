import { test } from "node:test";
import assert from "node:assert/strict";

test("aura scope_json rejects malformed JSON", async () => {
  const { parseAuraScopeJson } = await import("./auraScope.js");
  assert.throws(() => parseAuraScopeJson("{"), /scope_json_(missing|invalid)/);
});

test("aura scope_json rejects unknown keys", async () => {
  const { parseAuraScopeJson } = await import("./auraScope.js");
  assert.throws(
    () => parseAuraScopeJson(JSON.stringify({ domain: "social", extra: 1 })),
    /scope_json_invalid/
  );
});

test("aura scope_json rejects wrong domain for exact rule", async () => {
  const {
    parseAuraScopeJson,
    auraScopeToDerivedDomain,
    validateAuraScopeAgainstRuleDomainPattern
  } = await import("./auraScope.js");
  const scope = parseAuraScopeJson(JSON.stringify({ domain: "marketplace" }));
  const derivedDomain = auraScopeToDerivedDomain(scope);
  assert.throws(
    () =>
      validateAuraScopeAgainstRuleDomainPattern({
        ruleDomainPattern: "social",
        scope,
        derivedDomain
      }),
    /scope_domain_mismatch/
  );
});

test("aura scope_json rejects scope kind mismatch for space:*", async () => {
  const {
    parseAuraScopeJson,
    auraScopeToDerivedDomain,
    validateAuraScopeAgainstRuleDomainPattern
  } = await import("./auraScope.js");
  const scope = parseAuraScopeJson(JSON.stringify({ domain: "social" }));
  const derivedDomain = auraScopeToDerivedDomain(scope);
  assert.throws(
    () =>
      validateAuraScopeAgainstRuleDomainPattern({
        ruleDomainPattern: "space:*",
        scope,
        derivedDomain
      }),
    /scope_kind_mismatch/
  );
});
