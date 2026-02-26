import assert from "node:assert/strict";

process.env.NODE_ENV = "development";
process.env.HEDERA_NETWORK = "testnet";
process.env.SERVICE_JWT_SECRET_FORMAT_STRICT = "false";
process.env.ALLOW_INSECURE_DEV_AUTH = "true";

delete process.env.SERVICE_JWT_SECRET;
delete process.env.SERVICE_JWT_SECRET_DID;
delete process.env.SERVICE_JWT_SECRET_NEXT;

const { requireServiceAuth } = await import("../auth.ts");

const request = { headers: { authorization: "" } };
const reply = { sent: false, code() { return this; }, send() { this.sent = true; return this; } };

await requireServiceAuth(request, reply);
assert.equal(reply.sent, false);

