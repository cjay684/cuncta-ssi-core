import { z } from "zod";
import { getDb } from "./db.js";
import { ensureCatalogIntegrity } from "./catalogIntegrity.js";

export const CatalogEntrySchema = z.object({
  vct: z.string().min(1),
  json_schema: z.record(z.string(), z.unknown()),
  sd_defaults: z.array(z.string()),
  display: z.record(z.string(), z.unknown()),
  purpose_limits: z.record(z.string(), z.unknown()),
  presentation_templates: z.record(z.string(), z.unknown()),
  revocation_config: z.record(z.string(), z.unknown()),
  created_at: z.union([z.string(), z.date()]),
  updated_at: z.union([z.string(), z.date()])
});

export type CatalogEntry = z.infer<typeof CatalogEntrySchema>;

export const listCatalogEntries = async (): Promise<CatalogEntry[]> => {
  const db = await getDb();
  const rows = await db("credential_types").select("*").orderBy("vct");
  for (const row of rows) {
    await ensureCatalogIntegrity(row);
  }
  return z.array(CatalogEntrySchema).parse(rows);
};

export const getCatalogEntry = async (vct: string): Promise<CatalogEntry | null> => {
  const db = await getDb();
  const row = await db("credential_types").where({ vct }).first();
  if (!row) {
    return null;
  }
  await ensureCatalogIntegrity(row);
  return CatalogEntrySchema.parse(row);
};
