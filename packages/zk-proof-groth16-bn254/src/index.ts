import { createHash } from "node:crypto";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

export const PROOF_SYSTEM_ID = "groth16_bn254" as const;

// BN254 scalar field prime (aka bn128 Fr).
const SNARK_FIELD = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

const toField = (v: bigint) => {
  const x = v % SNARK_FIELD;
  return x >= 0n ? x : x + SNARK_FIELD;
};

export const sha256ToField = (value: string) => {
  const digest = createHash("sha256").update(value).digest();
  const asBig = BigInt("0x" + Buffer.from(digest).toString("hex"));
  return toField(asBig);
};

type SnarkjsGroth16 = {
  fullProve: (
    witness: Record<string, string>,
    wasmFile: string,
    zkeyFile: string
  ) => Promise<{ proof: unknown; publicSignals: string[] }>;
  verify: (verificationKey: unknown, publicSignals: string[], proof: unknown) => Promise<boolean>;
};
type Snarkjs = { groth16: SnarkjsGroth16 };

let cachedSnarkjs: Snarkjs | null = null;
const snark = (): Snarkjs => {
  if (!cachedSnarkjs) {
    cachedSnarkjs = require("snarkjs") as unknown as Snarkjs;
  }
  return cachedSnarkjs;
};

export const fullProveGroth16 = async (input: {
  witness: Record<string, string>;
  wasmFile: string;
  zkeyFile: string;
}) => {
  const start = Date.now();
  const { proof, publicSignals } = await snark().groth16.fullProve(input.witness, input.wasmFile, input.zkeyFile);
  return { proof, publicSignals, proveMs: Date.now() - start };
};

export const verifyGroth16 = async (input: {
  verificationKey: unknown;
  proof: unknown;
  publicSignals: string[];
}) => {
  const ok = await snark().groth16.verify(input.verificationKey, input.publicSignals, input.proof);
  return { ok: Boolean(ok) };
};

