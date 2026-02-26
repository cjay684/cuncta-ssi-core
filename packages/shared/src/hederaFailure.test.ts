import { strict as assert } from "node:assert";
import { classifyHederaFailure, extractHederaStatusFromError, extractTxIdFromError } from "./hederaFailure.js";

const run = async () => {
  assert.equal(extractTxIdFromError(new Error("no tx here")), undefined);
  assert.equal(extractTxIdFromError(new Error("receipt for transaction 0.0.123@170.1 contained error")), "0.0.123@170.1");

  assert.equal(
    extractHederaStatusFromError(
      new Error("receipt for transaction 0.0.123@170.1 contained error status FAIL_INVALID")
    ),
    "FAIL_INVALID"
  );

  const deterministic = classifyHederaFailure({
    name: "ReceiptStatusError",
    message: "receipt for transaction 0.0.1@170.1 contained error status INVALID_SIGNATURE",
    status: "INVALID_SIGNATURE"
  });
  assert.equal(deterministic.kind, "deterministic");
  assert.equal(deterministic.status, "INVALID_SIGNATURE");

  const transient = classifyHederaFailure({
    name: "ReceiptStatusError",
    message: "receipt for transaction 0.0.1@170.1 contained error status BUSY",
    status: "BUSY"
  });
  assert.equal(transient.kind, "transient");

  const unknown = classifyHederaFailure(
    new Error("receipt for transaction 0.0.1@170.1 contained error status FAIL_INVALID")
  );
  assert.equal(unknown.kind, "unknown");

  const timeout = classifyHederaFailure(new Error("Timed out waiting for receipt"));
  assert.equal(timeout.kind, "transient");
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});

