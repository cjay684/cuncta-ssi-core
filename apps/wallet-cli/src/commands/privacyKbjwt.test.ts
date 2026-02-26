import { strict as assert } from "node:assert";
import { decodeJwt } from "jose";
import { privacyKbjwt } from "./privacyKbjwt.js";

process.env.NODE_ENV = "test";

const run = async () => {
  const originalLog = console.log;
  const originalError = console.error;
  const logs: string[] = [];
  const errors: string[] = [];
  console.log = (...args: unknown[]) => {
    logs.push(args.map(String).join(" "));
  };
  console.error = (...args: unknown[]) => {
    errors.push(args.map(String).join(" "));
  };

  const restore = () => {
    console.log = originalLog;
    console.error = originalError;
  };

  try {
    const token = await privacyKbjwt({
      requestId: "req-1",
      nonce: "nonce-123",
      audience: "cuncta.privacy:request",
      output: () => undefined
    });
    const payload = decodeJwt(token) as Record<string, unknown>;
    assert.equal(payload.aud, "cuncta.privacy:request");
    assert.equal(payload.nonce, "nonce-123");
    assert.ok(typeof payload.iat === "number");
    assert.ok(typeof payload.exp === "number");
    assert.ok((payload.exp as number) > (payload.iat as number));
    assert.ok(payload.cnf && typeof payload.cnf === "object");
    const cnf = payload.cnf as Record<string, unknown>;
    assert.ok(cnf.jwk && typeof cnf.jwk === "object");

    process.env.KBJWT_TTL_SECONDS = "5";
    const lowToken = await privacyKbjwt({
      requestId: "req-2",
      nonce: "nonce-abc",
      audience: "cuncta.privacy:request",
      output: () => undefined
    });
    const lowPayload = decodeJwt(lowToken) as Record<string, unknown>;
    assert.equal((lowPayload.exp as number) - (lowPayload.iat as number), 30);

    process.env.KBJWT_TTL_SECONDS = "9999";
    const highToken = await privacyKbjwt({
      requestId: "req-3",
      nonce: "nonce-def",
      audience: "cuncta.privacy:request",
      output: () => undefined
    });
    const highPayload = decodeJwt(highToken) as Record<string, unknown>;
    assert.equal((highPayload.exp as number) - (highPayload.iat as number), 600);

    const allLogs = [...logs, ...errors].join(" ");
    assert.ok(!allLogs.includes(token));
    assert.ok(!allLogs.includes(lowToken));
    assert.ok(!allLogs.includes(highToken));
  } finally {
    restore();
    delete process.env.KBJWT_TTL_SECONDS;
  }
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
