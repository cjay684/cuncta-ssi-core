import path from "node:path";
import { loadConfig } from "./core/config.js";
import { createFileVault } from "./core/vault/fileVault.js";
import { listCredentials } from "./core/vault/records.js";

const main = async () => {
  const config = loadConfig();
  const vault = createFileVault({
    baseDir: path.resolve(process.cwd(), "apps", "mobile-wallet"),
    keyMaterial: config.WALLET_VAULT_KEY
  });
  await vault.init();
  const list = await listCredentials(vault);
  console.log(JSON.stringify(list, null, 2));
};

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
