import assert from "node:assert/strict";
import path from "node:path";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { commitDobDaysPoseidonV1Bn254Ds1, sha256ToField } from "@cuncta/zk-commitments-bn254";
import { fullProveGroth16, verifyGroth16 } from "@cuncta/zk-proof-groth16-bn254";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const pkgDir = path.resolve(__dirname, "..");

const artifactsDir = path.join(pkgDir, "artifacts", "age_gte_v1");
const wasmFile = path.join(artifactsDir, "age_gte_v1.wasm");
const zkeyFile = path.join(artifactsDir, "age_gte_v1.zkey");
const vkFile = path.join(artifactsDir, "age_gte_v1.verification_key.json");

const main = async () => {
  console.log("[zk-age-snark selftest] start");
  // Keep these within 32-bit due to LessEqThan(32) constraints in the circuit.
  const currentDay = 20_000;
  const minAge = 18;
  const ageDays = minAge * 365;
  const threshold = currentDay - ageDays;
  const birthdateDays = threshold; // just satisfies the constraint (<= threshold)

  const rand = 123456789n;
  const dobCommitment = await commitDobDaysPoseidonV1Bn254Ds1({ birthdateDays, rand });

  const nonceHash = sha256ToField("nonce:test");
  const audienceHash = sha256ToField("audience:test");
  const requestHash = sha256ToField("request_hash:test");

  console.log("[zk-age-snark selftest] proving...");
  const witness = {
    // private inputs
    birthdate_days: String(birthdateDays),
    rand: rand.toString(10),
    // public inputs
    dob_commitment: dobCommitment.toString(10),
    min_age: String(minAge),
    current_day: String(currentDay),
    nonce_hash: nonceHash.toString(10),
    audience_hash: audienceHash.toString(10),
    request_hash: requestHash.toString(10)
  } satisfies Record<string, string>;

  const verificationKey = JSON.parse(await readFile(vkFile, "utf8")) as unknown;

  const { proof, publicSignals } = await fullProveGroth16({ witness, wasmFile, zkeyFile });
  console.log("[zk-age-snark selftest] verifying...");
  const { ok } = await verifyGroth16({ verificationKey, proof, publicSignals });
  assert.equal(ok, true);

  // Ensure the public signals match the circuit's declared public order.
  assert.deepEqual(publicSignals, [
    witness.dob_commitment,
    witness.min_age,
    witness.current_day,
    witness.nonce_hash,
    witness.audience_hash,
    witness.request_hash
  ]);

  console.log("[zk-age-snark selftest] ok");
  // Force exit in case WASM/runtime leaves handles open on Windows.
  process.exit(0);
};

main().catch((err) => {
  // Keep output useful in CI / Windows terminals.
  console.error("[zk-age-snark selftest] failed:", err);
  process.exit(1);
});

