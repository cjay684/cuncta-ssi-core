import { strict as assert } from "node:assert";
import http from "node:http";
import { SignJWT, exportJWK, generateKeyPair } from "jose";

const run = async () => {
  process.env.NODE_ENV = "test";
  // Keep tests deterministic regardless of developer `.env`.
  process.env.HEDERA_NETWORK = "testnet";
  process.env.ALLOW_MAINNET = "false";
  process.env.POLICY_SERVICE_BASE_URL = "http://policy.test";
  process.env.SERVICE_JWT_SECRET = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  process.env.SERVICE_JWT_SECRET_VERIFIER = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

  const { privateKey, publicKey } = await generateKeyPair("EdDSA", { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  publicJwk.kid = "issuer-1";
  publicJwk.alg = "EdDSA";
  publicJwk.crv = "Ed25519";
  publicJwk.kty = "OKP";
  process.env.ISSUER_JWKS = JSON.stringify({ keys: [publicJwk] });

  const encodedList = Buffer.from(new Uint8Array([0])).toString("base64url");
  const vc = {
    "@context": ["https://www.w3.org/ns/credentials/v2", "https://w3id.org/vc/status-list/2021/v1"],
    type: ["VerifiableCredential", "BitstringStatusListCredential"],
    issuer: "did:example:issuer",
    issuanceDate: new Date().toISOString(),
    credentialSubject: {
      id: "http://issuer.test/status-lists/test",
      type: "BitstringStatusList",
      statusPurpose: "revocation",
      encodedList
    }
  };

  const proofJwt = await new SignJWT(vc as Record<string, unknown>)
    .setProtectedHeader({ alg: "EdDSA", typ: "status-list+jwt", kid: "issuer-1" })
    .setIssuedAt()
    .setIssuer("did:example:issuer")
    .sign(privateKey);

  const { privateKey: badPrivateKey } = await generateKeyPair("EdDSA", { extractable: true });
  const badJwt = await new SignJWT(vc as Record<string, unknown>)
    .setProtectedHeader({ alg: "EdDSA", typ: "status-list+jwt", kid: "issuer-2" })
    .setIssuedAt()
    .setIssuer("did:example:issuer")
    .sign(badPrivateKey);

  const server = http.createServer((req, res) => {
    if (!req.url) {
      res.writeHead(404);
      res.end();
      return;
    }
    if (req.url.startsWith("/status-lists/valid")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ...vc, proof: { type: "JwtProof2020", jwt: proofJwt } }));
      return;
    }
    if (req.url.startsWith("/status-lists/invalid")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ...vc, proof: { type: "JwtProof2020", jwt: badJwt } }));
      return;
    }
    res.writeHead(404);
    res.end();
  });

  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("test_server_failed");
  }
  process.env.ISSUER_SERVICE_BASE_URL = `http://127.0.0.1:${address.port}`;
  const { verifyStatusListEntry } = await import("./statusList.js");

  const ok = await verifyStatusListEntry({
    statusListCredential: `${process.env.ISSUER_SERVICE_BASE_URL}/status-lists/valid`,
    statusListIndex: "0"
  });
  assert.equal(ok.valid, true);

  const bad = await verifyStatusListEntry({
    statusListCredential: `${process.env.ISSUER_SERVICE_BASE_URL}/status-lists/invalid`,
    statusListIndex: "0"
  });
  assert.equal(bad.valid, false);
  assert.equal(bad.reason, "status_list_invalid_signature");

  const ssrf = await verifyStatusListEntry({
    statusListCredential: "http://example.com/status-lists/valid",
    statusListIndex: "0"
  });
  assert.equal(ssrf.valid, false);
  assert.equal(ssrf.reason, "status_list_url_invalid");

  const wrongPath = await verifyStatusListEntry({
    statusListCredential: `${process.env.ISSUER_SERVICE_BASE_URL}/jwks.json`,
    statusListIndex: "0"
  });
  assert.equal(wrongPath.valid, false);
  assert.equal(wrongPath.reason, "status_list_url_invalid");

  server.close();
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
