import { strict as assert } from "node:assert";

// Keep tests deterministic regardless of developer `.env`.
process.env.HEDERA_NETWORK = "testnet";
process.env.ALLOW_MAINNET = "false";

process.env.NODE_ENV = "development";
process.env.ALLOW_INSECURE_DEV_AUTH = "false";
process.env.ISSUER_SERVICE_BASE_URL = "http://issuer.test";
delete process.env.SERVICE_JWT_SECRET;
delete process.env.SERVICE_JWT_SECRET_VERIFIER;
delete process.env.SERVICE_JWT_SECRET_NEXT;

const run = async () => {
  const { requireServiceAuth } = await import("./auth.js");
  const reply = {
    statusCode: 200,
    payload: null as unknown,
    sent: false,
    code(status: number) {
      this.statusCode = status;
      return this;
    },
    send(payload: unknown) {
      this.payload = payload;
      this.sent = true;
      return this;
    }
  };
  const request = { headers: {} } as { headers: Record<string, string> };
  await requireServiceAuth(
    request as unknown as Parameters<typeof requireServiceAuth>[0],
    reply as unknown as Parameters<typeof requireServiceAuth>[1]
  );
  assert.equal(reply.statusCode, 503);
  assert.equal((reply.payload as { error?: string }).error, "service_auth_not_configured");
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
