import { base58btc } from "multiformats/bases/base58";

export const toBase58Multibase = (bytes: Uint8Array) => base58btc.encode(bytes);
