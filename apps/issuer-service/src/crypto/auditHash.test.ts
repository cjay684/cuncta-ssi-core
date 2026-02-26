import { strict as assert } from "node:assert";
import { hashCanonicalJson } from "@cuncta/shared";

const run = async () => {
  const payloadA = { event: "issue", data: { a: 1, b: 2 } };
  const payloadB = { data: { b: 2, a: 1 }, event: "issue" };
  const payloadC = { event: "issue", data: { a: 1, b: 3 } };

  const hashA = hashCanonicalJson(payloadA);
  const hashB = hashCanonicalJson(payloadB);
  const hashC = hashCanonicalJson(payloadC);

  assert.equal(hashA, hashB);
  assert.notEqual(hashA, hashC);
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
