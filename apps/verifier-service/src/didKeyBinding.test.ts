import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { base58btc } from "multiformats/bases/base58";
import { isCnfKeyAuthorizedByDidDocument } from "./didKeyBinding.js";

const toB64u = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

test("DID key binding: authorizes matching Ed25519 publicKeyJwk", () => {
  const did = "did:hedera:testnet:example";
  const cnfJwk = { kty: "OKP", crv: "Ed25519", x: toB64u(randomBytes(32)) };
  const didDoc = {
    id: did,
    verificationMethod: [
      {
        id: `${did}#key-1`,
        type: "JsonWebKey2020",
        controller: did,
        publicKeyJwk: cnfJwk
      }
    ],
    assertionMethod: [`${did}#key-1`]
  };
  assert.deepEqual(isCnfKeyAuthorizedByDidDocument(didDoc, cnfJwk), { ok: true });
});

test("DID key binding: denies when cnf key not present in DID document", () => {
  const did = "did:hedera:testnet:example";
  const didDoc = {
    id: did,
    verificationMethod: [
      {
        id: `${did}#key-1`,
        type: "JsonWebKey2020",
        controller: did,
        publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: toB64u(randomBytes(32)) }
      }
    ],
    assertionMethod: [`${did}#key-1`]
  };
  const cnfJwk = { kty: "OKP", crv: "Ed25519", x: toB64u(randomBytes(32)) };
  assert.deepEqual(isCnfKeyAuthorizedByDidDocument(didDoc, cnfJwk), {
    ok: false,
    reason: "did_key_not_authorized"
  });
});

test("DID key binding: authorizes matching Ed25519 publicKeyMultibase", () => {
  const did = "did:hedera:testnet:example";
  const pub = randomBytes(32);
  const didDoc = {
    id: did,
    verificationMethod: [
      {
        id: `${did}#key-1`,
        type: "Ed25519VerificationKey2020",
        controller: did,
        publicKeyMultibase: base58btc.encode(pub)
      }
    ],
    authentication: [`${did}#key-1`]
  };
  const cnfJwk = { kty: "OKP", crv: "Ed25519", x: toB64u(pub) };
  assert.deepEqual(isCnfKeyAuthorizedByDidDocument(didDoc, cnfJwk), { ok: true });
});

test("DID key binding: authorizes multicodec-wrapped Ed25519 publicKeyMultibase", () => {
  const did = "did:hedera:testnet:example";
  const pub = randomBytes(32);
  const multicodecWrapped = new Uint8Array([0xed, 0x01, ...pub]);
  const didDoc = {
    id: did,
    verificationMethod: [
      {
        id: `${did}#key-1`,
        type: "Ed25519VerificationKey2020",
        controller: did,
        publicKeyMultibase: base58btc.encode(multicodecWrapped)
      }
    ],
    assertionMethod: [`${did}#key-1`]
  };
  const cnfJwk = { kty: "OKP", crv: "Ed25519", x: toB64u(pub) };
  assert.deepEqual(isCnfKeyAuthorizedByDidDocument(didDoc, cnfJwk), { ok: true });
});
