import type { PayerKeyStore } from "./payerKeyStore.js";

// Mobile OS keystore implementation will be provided by platform adapters
// (Secure Enclave / Android Keystore) in the React Native runtime.
export const createMobilePayerKeyStore = (): PayerKeyStore => {
  throw new Error("mobile_payer_keystore_unavailable_in_node_runtime");
};

