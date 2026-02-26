import {
  AccountId,
  Client,
  Hbar,
  PrivateKey,
  PublicKey,
  TopicId,
  TopicMessageSubmitTransaction,
  TransactionId
} from "@hashgraph/sdk";
import { DIDOwnerMessage } from "@hiero-did-sdk/messages";
import { base58btc } from "multiformats/bases/base58";
import { createGatewayClient } from "../gateway/client.js";
import { KeyManager } from "../keys/types.js";
import { Vault } from "../vault/types.js";
import { WalletConfig } from "../config.js";
import { deriveUserPaysLimits } from "./limits.js";

const toBase64Url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

const buildUserPaysDidCreateTransaction = async (input: {
  message: DIDOwnerMessage;
  network: "testnet" | "previewnet" | "mainnet";
  topicId: string;
  payerAccountId: string;
  payerPrivateKey: string;
  maxFeeTinybars: number;
}) => {
  const hederaClient = Client.forName(input.network);
  // Keep this construction aligned with wallet-cli to avoid drift.
  // If retrying after a transport failure, regenerate TransactionId and re-sign.
  const transaction = new TopicMessageSubmitTransaction()
    .setTopicId(input.topicId)
    .setMessage(input.message.payload)
    .setTransactionId(TransactionId.generate(AccountId.fromString(input.payerAccountId)))
    .setMaxTransactionFee(Hbar.fromTinybars(input.maxFeeTinybars))
    .freezeWith(hederaClient);

  const signed = await transaction.sign(PrivateKey.fromString(input.payerPrivateKey));
  const signedBytes = signed.toBytes();
  if (typeof hederaClient.close === "function") {
    hederaClient.close();
  }

  return { did: input.message.did, signedBytes };
};

export const createDidViaGatewayUserPays = async (input: {
  config: WalletConfig;
  keyManager: KeyManager;
  vault: Vault;
}) => {
  const client = createGatewayClient(input.config.APP_GATEWAY_BASE_URL);
  const capabilities = await client.getCapabilities();
  if (!capabilities.selfFundedOnboarding.enabled) {
    throw new Error("gateway_self_funded_disabled");
  }
  if (capabilities.network !== input.config.HEDERA_NETWORK) {
    throw new Error("network_mismatch");
  }
  const state = await input.vault.getState();
  if (!state.payerRecord) {
    throw new Error("payer_record_missing");
  }
  const holderKeyRef = await input.keyManager.generateHolderKeypair();
  const holderPublicJwk = await input.keyManager.getHolderPublicJwk(holderKeyRef);
  const publicKeyBytes = Buffer.from(String(holderPublicJwk.x), "base64url");
  const publicKeyMultibase = base58btc.encode(publicKeyBytes);
  const request = await client.userPaysDidCreateRequest({
    network: input.config.HEDERA_NETWORK,
    publicKeyMultibase,
    deviceId: input.config.deviceId
  });
  const limits = deriveUserPaysLimits({
    walletMaxFeeTinybars: input.config.USER_PAYS_MAX_FEE_TINYBARS,
    gatewayMaxFeeTinybars: capabilities.selfFundedOnboarding.maxFeeTinybars,
    gatewayMaxTxBytes: capabilities.selfFundedOnboarding.maxTxBytes,
    gatewayRequestTtlSeconds: capabilities.selfFundedOnboarding.requestTtlSeconds,
    requestExpiresAt: request.expiresAt,
    nowMs: Date.now()
  });
  if (
    capabilities.selfFundedOnboarding.maxFeeTinybars !== undefined &&
    limits.effectiveMaxFeeTinybars < input.config.USER_PAYS_MAX_FEE_TINYBARS
  ) {
    console.log(
      "[wallet] fee_cap_applied",
      JSON.stringify({
        walletMaxFeeTinybars: input.config.USER_PAYS_MAX_FEE_TINYBARS,
        gatewayMaxFeeTinybars: capabilities.selfFundedOnboarding.maxFeeTinybars,
        effectiveMaxFeeTinybars: limits.effectiveMaxFeeTinybars
      })
    );
  }

  // Mirrors apps/wallet-cli/src/commands/didCreate.ts (user-pays gateway flow).
  const holderPublicKey = PublicKey.fromBytesED25519(publicKeyBytes);
  const topicId = TopicId.fromString(request.topicId).toString();
  const message = new DIDOwnerMessage({
    publicKey: holderPublicKey,
    network: request.network,
    topicId
  });
  const holderSignature = await input.keyManager.signWithHolderKey(
    holderKeyRef,
    message.messageBytes
  );
  message.signature = holderSignature;

  const payerAccountId = await input.keyManager.getPayerAccountId(state.payerRecord.payerRef);
  const payerKeyRecord = state.payerKeys[state.payerRecord.payerRef.id];
  if (!payerKeyRecord) {
    throw new Error("payer_key_missing");
  }

  const { did, signedBytes } = await buildUserPaysDidCreateTransaction({
    message,
    network: request.network,
    topicId,
    payerAccountId,
    payerPrivateKey: payerKeyRecord.privateKey,
    maxFeeTinybars: limits.effectiveMaxFeeTinybars
  });
  if (limits.gatewayMaxTxBytes !== undefined && signedBytes.length > limits.gatewayMaxTxBytes) {
    throw new Error("signed_transaction_too_large");
  }
  if (Date.now() > limits.effectiveExpiryMs) {
    throw new Error("request_expired");
  }

  const submit = await client.userPaysDidCreateSubmit({
    handoffToken: request.handoffToken,
    signedTransactionB64u: toBase64Url(signedBytes),
    deviceId: input.config.deviceId
  });

  const didRecord = {
    did,
    holderKeyRef,
    network: request.network,
    createdAt: new Date().toISOString()
  };
  state.didRecord = didRecord;
  await input.vault.setState(state);
  return { did, topicId, transactionId: submit.transactionId ?? "" };
};
