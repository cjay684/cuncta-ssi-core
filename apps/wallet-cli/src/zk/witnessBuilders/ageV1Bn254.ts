import type { WalletZkWitnessBuilder } from "./types.js";
import { sha256ToField } from "@cuncta/zk-proof-groth16-bn254";
import { commitDobDaysPoseidonV1Bn254Ds1 } from "@cuncta/zk-commitments-bn254";

// BN254 scalar field prime (aka bn128 Fr).
const SNARK_FIELD = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

const toInt = (v: unknown) => {
  const n = Number(v);
  if (!Number.isInteger(n)) throw new Error("witness_input_invalid_integer");
  return n;
};

const toBigintString = (v: unknown) => {
  if (typeof v === "bigint") return v.toString();
  if (typeof v === "number" && Number.isInteger(v)) return BigInt(v).toString();
  if (typeof v !== "string" || !v.trim()) throw new Error("witness_input_invalid_bigint_string");
  // Throws if invalid.
  return BigInt(v).toString();
};

// Witness builder for the current MVP circuit: age >= min_age.
//
// IMPORTANT: This module is keyed by a registry `witness_builder_id`, not by statement_id.
export const buildWitnessAgeV1Bn254: WalletZkWitnessBuilder = async (input) => {
  const minAge = toInt(input.params.min_age);
  const currentDay = toInt(input.zkContext.current_day);

  const birthdateDays = toInt(input.secrets.birthdate_days);
  const rand = toBigintString(input.secrets.rand);

  const dobCommitment = toBigintString(input.disclosedClaims.dob_commitment);

  // Fail fast with actionable errors (avoid opaque circom "Assert Failed" dumps).
  const threshold = currentDay - minAge * 365;
  if (currentDay < minAge * 365) {
    throw new Error(`witness_current_day_too_small currentDay=${currentDay} minAge=${minAge}`);
  }
  if (birthdateDays > threshold) {
    throw new Error(
      `witness_age_not_satisfied birthdateDays=${birthdateDays} currentDay=${currentDay} minAge=${minAge} threshold=${threshold}`
    );
  }
  try {
    const r = BigInt(rand);
    if (r < 0n || r >= SNARK_FIELD) {
      throw new Error("witness_rand_out_of_field");
    }
    const recomputed = await commitDobDaysPoseidonV1Bn254Ds1({ birthdateDays, rand: r });
    if (recomputed.toString() !== BigInt(dobCommitment).toString()) {
      throw new Error(
        `witness_commitment_mismatch expected=${dobCommitment} recomputed=${recomputed.toString()}`
      );
    }
  } catch (err) {
    throw new Error(
      `witness_commitment_check_failed:${err instanceof Error ? err.message : "unknown"}`
    );
  }

  return {
    // Public inputs
    dob_commitment: dobCommitment,
    min_age: String(minAge),
    current_day: String(currentDay),
    nonce_hash: sha256ToField(input.bindings.nonce).toString(),
    audience_hash: sha256ToField(input.bindings.audience).toString(),
    request_hash: sha256ToField(input.bindings.requestHash).toString(),

    // Private witness
    birthdate_days: String(birthdateDays),
    rand
  };
};
