import { Vault, DidRecord, PayerRecord } from "./types.js";
import { randomUUID } from "node:crypto";

export const setDidRecord = async (vault: Vault, record: DidRecord) => {
  const state = await vault.getState();
  state.didRecord = record;
  await vault.setState(state);
};

export const getDidRecord = async (vault: Vault) => {
  const state = await vault.getState();
  return state.didRecord ?? null;
};

export const setPayerRecord = async (vault: Vault, record: PayerRecord) => {
  const state = await vault.getState();
  state.payerRecord = record;
  await vault.setState(state);
};

export const getPayerRecord = async (vault: Vault) => {
  const state = await vault.getState();
  return state.payerRecord ?? null;
};

export const addCredential = async (
  vault: Vault,
  input: {
    sdJwt: string;
    network: string;
    issuerDid?: string;
    type?: string;
    vct?: string;
  }
) => {
  const id = randomUUID();
  const state = await vault.getState();
  state.credentials[id] = {
    id,
    network: input.network,
    issuerDid: input.issuerDid,
    type: input.type,
    vct: input.vct,
    sdJwt: input.sdJwt,
    storedAt: new Date().toISOString()
  };
  await vault.setState(state);
  return id;
};

export const listCredentials = async (vault: Vault) => {
  const state = await vault.getState();
  return Object.values(state.credentials).map(({ sdJwt: _sdJwt, ...meta }) => meta);
};

export const getCredential = async (vault: Vault, id: string) => {
  const state = await vault.getState();
  return state.credentials[id] ?? null;
};

export const deleteCredential = async (vault: Vault, id: string) => {
  const state = await vault.getState();
  delete state.credentials[id];
  await vault.setState(state);
};
