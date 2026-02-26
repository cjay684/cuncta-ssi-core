import { Vault } from "../vault/types.js";
import { createHash } from "node:crypto";

export type RelyingPartyRecord = {
  aud: string;
  audHash: string;
  displayName?: string;
  firstSeenAt: string;
  lastSeenAt: string;
  policyHash?: string;
  pinnedPolicyHash?: string;
};

export const computeAudHash = (aud: string) =>
  createHash("sha256").update(`aud:${aud}`, "utf8").digest("base64url");

export const formatRelyingPartyLog = (input: {
  audHash: string;
  firstSeen: boolean;
  policyChanged: boolean;
}) =>
  `[wallet] relying_party_status ${JSON.stringify({
    audHash: input.audHash,
    firstSeen: input.firstSeen,
    policyChanged: input.policyChanged
  })}`;

export const getRelyingParty = async (vault: Vault, aud: string) => {
  const state = await vault.getState();
  return state.relyingParties[aud] ?? null;
};

export const rememberRelyingParty = async (
  vault: Vault,
  record: Omit<RelyingPartyRecord, "audHash"> & { audHash?: string }
) => {
  const state = await vault.getState();
  const existing = state.relyingParties[record.aud];
  const now = new Date().toISOString();
  const pinnedPolicyHash = existing?.pinnedPolicyHash ?? record.policyHash;
  state.relyingParties[record.aud] = {
    aud: record.aud,
    audHash: record.audHash ?? computeAudHash(record.aud),
    displayName: record.displayName ?? existing?.displayName,
    firstSeenAt: existing?.firstSeenAt ?? record.firstSeenAt ?? now,
    lastSeenAt: now,
    policyHash: record.policyHash ?? existing?.policyHash,
    pinnedPolicyHash
  };
  await vault.setState(state);
};

export const checkRelyingPartyStatus = async (
  vault: Vault,
  input: { aud: string; policyHash?: string }
) => {
  const existing = await getRelyingParty(vault, input.aud);
  const firstSeen = !existing;
  const hashChanged =
    Boolean(existing?.pinnedPolicyHash && input.policyHash) &&
    existing?.pinnedPolicyHash !== input.policyHash;
  return { firstSeen, hashChanged, existing };
};
