import type { WalletKeyStore } from "./types.js";

// Browser-backed implementation is expected to use WebCrypto + IndexedDB.
// This placeholder fails closed in non-browser runtimes.
export const createWebCryptoKeyStore = (): WalletKeyStore => {
  throw new Error("webcrypto_keystore_unavailable_in_node_runtime");
};

