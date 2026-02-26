import { Client as HieroClient } from "@hiero-ledger/sdk";
import {
  Client as HashgraphClient,
  Hbar,
  TopicCreateTransaction,
  TopicMessageSubmitTransaction
} from "@hashgraph/sdk";

export type HederaNetwork = "testnet" | "previewnet" | "mainnet";

export function createHederaClient(network: HederaNetwork) {
  try {
    return HashgraphClient.forName(network);
  } catch {
    return HieroClient.forName(network);
  }
}

export function buildHederaClient(
  network: HederaNetwork,
  operatorId: string,
  operatorPrivateKey: string
) {
  const client = createHederaClient(network) as unknown as {
    setOperator?: (id: string, key: string) => void;
    setOperatorWith?: (id: string, key: string) => void;
  };
  try {
    if (client.setOperatorWith) {
      client.setOperatorWith(operatorId, operatorPrivateKey);
    } else if (client.setOperator) {
      client.setOperator(operatorId, operatorPrivateKey);
    }
    return client as unknown;
  } catch {
    const fallback = HashgraphClient.forName(network);
    fallback.setOperator(operatorId, operatorPrivateKey);
    return fallback as unknown;
  }
}

export async function ensureTopic(client: unknown, topicId?: string) {
  if (topicId) {
    return topicId;
  }
  const tx = await new TopicCreateTransaction().execute(client as HashgraphClient);
  const receipt = await tx.getReceipt(client as HashgraphClient);
  return receipt.topicId?.toString() ?? "";
}

export async function publishAnchorMessage(
  client: unknown,
  topicId: string,
  message: { kind: string; sha256: string; metadata?: Record<string, unknown> },
  options?: { maxFeeTinybars?: number; maxMessageBytes?: number }
) {
  const text = JSON.stringify(message);
  const bytes = Buffer.from(text, "utf8");
  const maxMessageBytes = options?.maxMessageBytes;
  if (typeof maxMessageBytes === "number" && bytes.length > maxMessageBytes) {
    throw new Error("anchor_message_too_large");
  }
  const builder = new TopicMessageSubmitTransaction().setTopicId(topicId).setMessage(bytes);
  if (typeof options?.maxFeeTinybars === "number" && Number.isFinite(options.maxFeeTinybars)) {
    builder.setMaxTransactionFee(Hbar.fromTinybars(Math.floor(options.maxFeeTinybars)));
  }
  const tx = await builder.execute(client as HashgraphClient);
  const receipt = await tx.getReceipt(client as HashgraphClient);
  const transactionId = tx.transactionId?.toString() ?? "";
  const record = await tx.getRecord(client as HashgraphClient);
  return {
    topicId,
    transactionId,
    sequenceNumber: receipt.topicSequenceNumber?.toString() ?? "",
    consensusTimestamp: record.consensusTimestamp?.toString() ?? ""
  };
}

export {
  fetchTopicMessages,
  fetchTopicMessageBySequence,
  type FetchTopicMessagesOptions,
  type MirrorTopicMessage,
  type MirrorOrder
} from "./mirror.js";

export {
  applyTopicSubmitMaxFee,
  defaultFeeBudgets,
  enforceSignedTopicMessageSubmitBudget,
  extractMaxFeeTinybars,
  parseFeeBudgetsJson,
  type FeeBudgets,
  type TxBudget
} from "./feeBudget.js";
