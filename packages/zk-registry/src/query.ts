import { loadZkStatementRegistry } from "./loader.js";

export const listZkStatements = async () => {
  const reg = await loadZkStatementRegistry();
  return Array.from(reg.values());
};

export const listIssuableCredentialConfigs = async () => {
  const reg = await loadZkStatementRegistry();
  const configs = new Map<
    string,
    {
      credential_configuration_id: string;
      format: "dc+sd-jwt" | "di+bbs";
      vct: string;
      statement_ids: string[];
    }
  >();

  for (const entry of reg.values()) {
    const def = entry.definition;
    if (!entry.available) continue;
    if (!def.issuance?.enabled) continue;
    const id = def.credential.credential_config_id;
    const existing = configs.get(id);
    if (!existing) {
      configs.set(id, {
        credential_configuration_id: id,
        format: def.credential.format,
        vct: def.credential.vct,
        statement_ids: [def.statement_id]
      });
    } else {
      existing.statement_ids.push(def.statement_id);
    }
  }

  return Array.from(configs.values());
};

export const getZkStatementsForCredentialConfig = async (credentialConfigurationId: string) => {
  const reg = await loadZkStatementRegistry();
  const out = [];
  for (const entry of reg.values()) {
    if (!entry.available) continue;
    if (entry.definition.credential.credential_config_id === credentialConfigurationId) {
      out.push(entry);
    }
  }
  return out;
};

