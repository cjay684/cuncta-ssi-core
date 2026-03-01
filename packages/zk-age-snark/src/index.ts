import { createHash, randomBytes } from "node:crypto";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
// These dependencies ship without TS types; keep them `unknown` and narrow locally.
// (We intentionally avoid static `import` to keep consumer projects typechecking clean.)
type SnarkjsGroth16 = {
  fullProve: (
    witness: Record<string, string>,
    wasmFile: string,
    zkeyFile: string
  ) => Promise<{ proof: unknown; publicSignals: string[] }>;
  verify: (verificationKey: unknown, publicSignals: string[], proof: unknown) => Promise<boolean>;
};
type Snarkjs = { groth16: SnarkjsGroth16 };

type PoseidonFn = ((inputs: bigint[]) => unknown) & {
  F: { toObject: (value: unknown) => bigint | number | string };
};
type CircomlibJs = { buildPoseidon: () => Promise<PoseidonFn> };

let cachedSnarkjs: Snarkjs | null = null;
const snark = (): Snarkjs => {
  if (!cachedSnarkjs) {
    cachedSnarkjs = require("snarkjs") as unknown as Snarkjs;
  }
  return cachedSnarkjs;
};

let cachedCircomlib: CircomlibJs | null = null;
const circomlib = (): CircomlibJs => {
  if (!cachedCircomlib) {
    cachedCircomlib = require("circomlibjs") as unknown as CircomlibJs;
  }
  return cachedCircomlib;
};

// BN254 scalar field prime used by snarkjs circuits.
const SNARK_FIELD = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

// Domain separation tag for DOB commitments:
// sha256("cuncta:age:v1") mod p
export const AGE_COMMITMENT_DOMAIN_TAG =
  3805445632897706479387916969139462601971875644687406422943513851068976456195n;

const toField = (v: bigint) => {
  const x = v % SNARK_FIELD;
  return x >= 0n ? x : x + SNARK_FIELD;
};

export const sha256ToField = (value: string) => {
  const digest = createHash("sha256").update(value).digest();
  const asBig = BigInt("0x" + Buffer.from(digest).toString("hex"));
  return toField(asBig);
};

export const randomField = () => {
  const bytes = randomBytes(32);
  const asBig = BigInt("0x" + Buffer.from(bytes).toString("hex"));
  return toField(asBig);
};

let cachedPoseidon: PoseidonFn | null = null;
const poseidon = async () => {
  if (!cachedPoseidon) cachedPoseidon = await circomlib().buildPoseidon();
  return cachedPoseidon;
};

export const commitDobDaysPoseidon = async (input: { birthdateDays: number; rand: bigint }) => {
  const p = await poseidon();
  const out = p([AGE_COMMITMENT_DOMAIN_TAG, BigInt(input.birthdateDays), toField(input.rand)]);
  // circomlibjs Poseidon returns a field element; use its field helper to normalize.
  const asBig = BigInt(p.F.toObject(out));
  return toField(asBig);
};

export const computeBindings = (input: {
  nonce: string;
  audience: string;
  requestHash: string;
}) => {
  return {
    nonce_hash: sha256ToField(input.nonce),
    audience_hash: sha256ToField(input.audience),
    request_hash: sha256ToField(input.requestHash)
  };
};

export const artifactsPath = () => {
  // Resolved by consumers; keep it relative-friendly.
  return new URL("../artifacts/age_gte_v1/", import.meta.url);
};

export type Groth16Proof = {
  pi_a: [string, string, string];
  pi_b: [[string, string], [string, string], [string, string]];
  pi_c: [string, string, string];
  protocol: "groth16";
  curve: "bn128";
};

export type AgeGtePublicSignals = string[];

export const proveAgeGteV1 = async (input: {
  birthdateDays: number;
  rand: bigint;
  dobCommitment: bigint;
  minAge: number;
  currentDay: number;
  nonce: string;
  audience: string;
  requestHash: string;
  wasmFile: string;
  zkeyFile: string;
}) => {
  const bindings = computeBindings({
    nonce: input.nonce,
    audience: input.audience,
    requestHash: input.requestHash
  });
  const witness = {
    birthdate_days: String(input.birthdateDays),
    rand: String(toField(input.rand)),
    dob_commitment: String(toField(input.dobCommitment)),
    min_age: String(input.minAge),
    current_day: String(input.currentDay),
    nonce_hash: String(bindings.nonce_hash),
    audience_hash: String(bindings.audience_hash),
    request_hash: String(bindings.request_hash)
  };

  const start = Date.now();
  const { proof, publicSignals } = await snark().groth16.fullProve(
    witness,
    input.wasmFile,
    input.zkeyFile
  );
  return {
    proof: proof as Groth16Proof,
    publicSignals: publicSignals as AgeGtePublicSignals,
    proveMs: Date.now() - start,
    bindings
  };
};

export const verifyGroth16 = async (input: {
  verificationKey: unknown;
  proof: unknown;
  publicSignals: string[];
}) => {
  const ok = await snark().groth16.verify(input.verificationKey, input.publicSignals, input.proof);
  return { ok: Boolean(ok) };
};
