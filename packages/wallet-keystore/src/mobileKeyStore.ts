import type { WalletKeyStore } from "./types.js";

// React Native hardware-backed implementation is provided by platform-specific
// adapters (Secure Enclave / Android Keystore). Node runtime fails closed.
export const createMobileKeyStore = (): WalletKeyStore => {
  throw new Error("mobile_keystore_unavailable_in_node_runtime");
};
