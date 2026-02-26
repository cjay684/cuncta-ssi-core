import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { getPublicKey, hashes, sign } from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { base58btc } from "multiformats/bases/base58";
import { config } from "../config.js";
import { log } from "../log.js";
import { readJson, writeJson } from "../storage/jsonStore.js";

if (!hashes.sha512) {
  hashes.sha512 = sha512;
}

type IssuerDidRecord = {
  issuerDid: string;
  hedera: {
    topicId: string;
    transactionId: string;
  };
  keys: {
    ed25519: {
      privateKeyBase64: string;
      publicKeyBase64: string;
      publicKeyMultibase: string;
    };
  };
};

type WalletState = {
  did?: {
    did?: string;
  };
};

const dataDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "data");
const issuerDidPath = path.join(dataDir, "issuer-did.json");
const repoRoot = path.resolve(dataDir, "..", "..", "..");
const walletStatePath = path.join(repoRoot, "apps", "wallet-cli", "wallet-state.json");

const toBase64Url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const fromBase64Url = (value: string) => new Uint8Array(Buffer.from(value, "base64url"));

const requestSchema = z.object({
  state: z.string().uuid(),
  signingRequest: z.object({
    publicKeyMultibase: z.string(),
    alg: z.literal("EdDSA"),
    payloadToSignB64u: z.string(),
    createdAt: z.string()
  })
});

const submitSchema = z.object({
  did: z.string(),
  didDocument: z.unknown(),
  hedera: z.object({
    topicId: z.string(),
    transactionId: z.string()
  })
});

const loadHolderDid = async (): Promise<string | null> => {
  try {
    const content = await readFile(walletStatePath, "utf8");
    const state = JSON.parse(content) as WalletState;
    return state.did?.did ?? null;
  } catch {
    return null;
  }
};

const isValidRecord = (record: IssuerDidRecord | null): record is IssuerDidRecord => {
  if (!record) return false;
  const keys = record.keys?.ed25519;
  return Boolean(
    record.issuerDid &&
    record.hedera?.topicId &&
    keys?.privateKeyBase64 &&
    keys?.publicKeyBase64 &&
    keys?.publicKeyMultibase
  );
};

const createIssuerDid = async (): Promise<IssuerDidRecord> => {
  const network = "testnet";
  const serviceUrl = new URL(config.DID_SERVICE_BASE_URL);

  const privateKey = randomBytes(32);
  const publicKey = await getPublicKey(privateKey);
  const publicKeyMultibase = base58btc.encode(publicKey);
  if (!publicKeyMultibase.startsWith("z")) {
    throw new Error("public_key_multibase_invalid");
  }

  const createResponse = await fetch(new URL("/v1/dids/create/request", serviceUrl), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      network,
      publicKeyMultibase,
      options: { topicManagement: "shared", includeServiceEndpoints: true }
    })
  });
  if (!createResponse.ok) {
    const errorText = await createResponse.text();
    throw new Error(`issuer_did_create_request_failed: ${errorText}`);
  }

  const createPayload = requestSchema.parse(await createResponse.json());
  if (createPayload.signingRequest.publicKeyMultibase !== publicKeyMultibase) {
    throw new Error("issuer_public_key_multibase_mismatch");
  }

  const payloadToSign = fromBase64Url(createPayload.signingRequest.payloadToSignB64u);
  const signature = await sign(payloadToSign, privateKey);

  const submitResponse = await fetch(new URL("/v1/dids/create/submit", serviceUrl), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      state: createPayload.state,
      signatureB64u: toBase64Url(signature)
    })
  });
  if (!submitResponse.ok) {
    const errorText = await submitResponse.text();
    throw new Error(`issuer_did_create_submit_failed: ${errorText}`);
  }

  const submitPayload = submitSchema.parse(await submitResponse.json());

  const record: IssuerDidRecord = {
    issuerDid: submitPayload.did,
    hedera: {
      topicId: submitPayload.hedera.topicId,
      transactionId: submitPayload.hedera.transactionId
    },
    keys: {
      ed25519: {
        privateKeyBase64: Buffer.from(privateKey).toString("base64"),
        publicKeyBase64: Buffer.from(publicKey).toString("base64"),
        publicKeyMultibase
      }
    }
  };

  await writeJson(issuerDidPath, record);
  return record;
};

let warnedInvalidIssuerDid = false;

export const bootstrapIssuerDid = async (): Promise<IssuerDidRecord> => {
  const existing = await readJson<IssuerDidRecord | null>(issuerDidPath, null);
  if (isValidRecord(existing)) {
    return existing;
  }

  const holderDid = await loadHolderDid();
  const envIssuerDid = process.env.ISSUER_DID;
  if (envIssuerDid && holderDid && envIssuerDid === holderDid && !warnedInvalidIssuerDid) {
    warnedInvalidIssuerDid = true;
    log.warn("issuer.did.invalid", { reason: "issuer_equals_holder" });
  }

  return createIssuerDid();
};
