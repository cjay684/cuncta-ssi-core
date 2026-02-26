import assert from "node:assert/strict";

process.env.NODE_ENV = "development";
process.env.HEDERA_NETWORK = "testnet";
process.env.SERVICE_JWT_SECRET_FORMAT_STRICT = "false";
process.env.ALLOW_INSECURE_DEV_AUTH = "false";

delete process.env.SERVICE_JWT_SECRET;
delete process.env.SERVICE_JWT_SECRET_DID;
delete process.env.SERVICE_JWT_SECRET_NEXT;

const { requireServiceAuth } = await import("../auth.ts");

const request = { headers: { authorization: "" } };
const reply = (() => {
  const state = { status: 200, sent: false };
  return {
    get sent() {
      return state.sent;
    },
    code(code) {
      state.status = code;
      return this;
    },
    send() {
      state.sent = true;
      return this;
    },
    __state: state
  };
})();

await requireServiceAuth(request, reply);
assert.equal(reply.__state.sent, true);
assert.equal(reply.__state.status, 503);

