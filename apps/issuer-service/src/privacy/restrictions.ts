import { getDb } from "../db.js";
import { getLookupHashes } from "../pseudonymizer.js";

export type PrivacyStatus = {
  restricted: boolean;
  tombstoned: boolean;
};

export const getPrivacyStatus = async (hashes: {
  primary: string;
  legacy?: string | null;
}): Promise<PrivacyStatus> => {
  const db = await getDb();
  const lookup = getLookupHashes(hashes);
  const [restriction, tombstone] = await Promise.all([
    db("privacy_restrictions").whereIn("did_hash", lookup).first(),
    db("privacy_tombstones").whereIn("did_hash", lookup).first()
  ]);
  return { restricted: Boolean(restriction), tombstoned: Boolean(tombstone) };
};
