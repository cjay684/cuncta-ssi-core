import { strict as assert } from "node:assert";

// Keep tests deterministic regardless of developer `.env`.
process.env.HEDERA_NETWORK = "testnet";
process.env.ALLOW_MAINNET = "false";

process.env.NODE_ENV = "test";
process.env.ISSUER_SERVICE_BASE_URL = "http://issuer.test";
process.env.POLICY_SERVICE_BASE_URL = "http://policy.test";
process.env.SERVICE_JWT_SECRET = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
process.env.SERVICE_JWT_SECRET_VERIFIER = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
process.env.STATUS_LIST_CACHE_TTL_SECONDS = "1";
process.env.STATUS_LIST_CACHE_MAX_ENTRIES = "2";

const run = async () => {
  const { config } = await import("./config.js");
  const { __test__ } = await import("./statusList.js");
  config.STATUS_LIST_CACHE_MAX_ENTRIES = 2;

  __test__.resetCache();
  const now = Date.now();
  __test__.setCacheEntry("a", { encodedList: "a", fetchedAt: now });
  __test__.setCacheEntry("b", { encodedList: "b", fetchedAt: now });
  __test__.setCacheEntry("c", { encodedList: "c", fetchedAt: now });

  const keys = __test__.getCacheKeys();
  assert.deepEqual(keys, ["b", "c"]);

  const fresh = __test__.isCacheFresh({ encodedList: "x", fetchedAt: now }, now + 500);
  const stale = __test__.isCacheFresh({ encodedList: "x", fetchedAt: now }, now + 1500);
  assert.equal(fresh, true);
  assert.equal(stale, false);
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
