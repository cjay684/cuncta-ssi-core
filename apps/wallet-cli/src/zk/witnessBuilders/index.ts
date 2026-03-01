import type { WalletZkWitnessBuilder } from "./types.js";
import { buildWitnessAgeV1Bn254 } from "./ageV1Bn254.js";

export const getWalletWitnessBuilder = (id: string): WalletZkWitnessBuilder | null => {
  // This is intentionally keyed by registry-provided builder IDs.
  // Adding a new ZK statement should only require adding a new builder module + one entry here.
  const map: Record<string, WalletZkWitnessBuilder> = {
    "witness:age_v1_bn254": buildWitnessAgeV1Bn254
  };
  return map[id] ?? null;
};
