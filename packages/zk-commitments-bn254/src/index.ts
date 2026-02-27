import { createHash, randomBytes } from "node:crypto";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

// BN254 scalar field prime (aka bn128 Fr).
const SNARK_FIELD = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

const toField = (v: bigint) => {
  const x = v % SNARK_FIELD;
  return x >= 0n ? x : x + SNARK_FIELD;
};

export const randomField = () => {
  const bytes = randomBytes(32);
  const asBig = BigInt("0x" + Buffer.from(bytes).toString("hex"));
  return toField(asBig);
};

export const sha256ToField = (value: string) => {
  const digest = createHash("sha256").update(value).digest();
  const asBig = BigInt("0x" + Buffer.from(digest).toString("hex"));
  return toField(asBig);
};

type PoseidonFn = ((inputs: bigint[]) => unknown) & {
  F: { toObject: (value: unknown) => bigint | number | string };
};
type CircomlibJs = { buildPoseidon: () => Promise<PoseidonFn> };

let cachedCircomlib: CircomlibJs | null = null;
const circomlib = (): CircomlibJs => {
  if (!cachedCircomlib) cachedCircomlib = require("circomlibjs") as unknown as CircomlibJs;
  return cachedCircomlib;
};

let cachedPoseidon: PoseidonFn | null = null;
const poseidon = async () => {
  if (!cachedPoseidon) cachedPoseidon = await circomlib().buildPoseidon();
  return cachedPoseidon;
};

// Domain separation tag for DOB commitments:
// sha256("cuncta:age:v1") mod p
export const AGE_COMMITMENT_DOMAIN_TAG =
  3805445632897706479387916969139462601971875644687406422943513851068976456195n;

export const commitDobDaysPoseidonV1Bn254Ds1 = async (input: {
  birthdateDays: number;
  rand: bigint;
}) => {
  const p = await poseidon();
  const out = p([AGE_COMMITMENT_DOMAIN_TAG, BigInt(input.birthdateDays), toField(input.rand)]);
  const asBig = BigInt(p.F.toObject(out));
  return toField(asBig);
};
