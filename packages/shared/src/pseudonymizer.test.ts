import { strict as assert } from "node:assert";
import { createHmac } from "node:crypto";
import { createHmacSha256Pseudonymizer } from "./pseudonymizer.js";

const run = () => {
  const pepper = "test-pepper";
  const did = "did:example:alice";
  const pseudonymizer = createHmacSha256Pseudonymizer({ pepper });
  const first = pseudonymizer.didToHash(did);
  const second = pseudonymizer.didToHash(did);

  const expected = createHmac("sha256", pepper).update(did).digest("hex").toLowerCase();
  assert.equal(first, expected);
  assert.equal(second, expected);
  assert.equal(first, first.toLowerCase());
};

try {
  run();
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
