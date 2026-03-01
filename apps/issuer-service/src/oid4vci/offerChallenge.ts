import { randomBytes, createHash } from "node:crypto";
import { getDb } from "../db.js";
import { config } from "../config.js";

const sha256Hex = (value: string) => createHash("sha256").update(value).digest("hex");

export const createOfferChallenge = async () => {
  const db = await getDb();
  const nonce = randomBytes(32).toString("base64url");
  const nonceHash = sha256Hex(nonce);
  const expiresAt = new Date(
    Date.now() + config.OID4VCI_OFFER_CHALLENGE_TTL_SECONDS * 1000
  ).toISOString();
  await db("oid4vci_offer_challenges").insert({
    nonce_hash: nonceHash,
    expires_at: expiresAt,
    consumed_at: null,
    created_at: new Date().toISOString()
  });
  return { nonce, expiresAt };
};

export const consumeOfferChallenge = async (input: { nonce: string }) => {
  const db = await getDb();
  const nonceHash = sha256Hex(input.nonce);
  const now = new Date().toISOString();
  const updated = await db("oid4vci_offer_challenges")
    .where({ nonce_hash: nonceHash })
    .whereNull("consumed_at")
    .andWhere("expires_at", ">", now)
    .update({ consumed_at: now });
  if (!updated) {
    throw new Error("offer_challenge_invalid_or_consumed");
  }
};
