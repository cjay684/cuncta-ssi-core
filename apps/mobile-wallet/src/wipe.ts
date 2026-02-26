import path from "node:path";
import { loadConfig } from "./core/config.js";
import { createFileVault, resolveVaultKey } from "./core/vault/fileVault.js";

const main = async () => {
  const config = loadConfig();
  const vaultKey = await resolveVaultKey(config);
  const vault = createFileVault({
    baseDir: path.resolve(process.cwd(), "apps", "mobile-wallet"),
    keyMaterial: vaultKey
  });
  await vault.wipe();
  console.log("[wallet] vault wiped");
};

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
