import path from "node:path";
import { loadConfig, assertSoftwareKeysAllowed } from "./core/config.js";
import { createFileVault } from "./core/vault/fileVault.js";
import { addCredential } from "./core/vault/records.js";

const main = async () => {
  const config = loadConfig();
  assertSoftwareKeysAllowed(config);

  const sdJwt = process.env.WALLET_SD_JWT;
  if (!sdJwt) {
    throw new Error("WALLET_SD_JWT is required");
  }
  const vault = createFileVault({
    baseDir: path.resolve(process.cwd(), "apps", "mobile-wallet"),
    keyMaterial: config.WALLET_VAULT_KEY
  });
  await vault.init();

  const id = await addCredential(vault, {
    sdJwt,
    network: config.HEDERA_NETWORK,
    issuerDid: process.env.WALLET_CREDENTIAL_ISSUER_DID,
    type: process.env.WALLET_CREDENTIAL_TYPE,
    vct: process.env.WALLET_CREDENTIAL_VCT
  });
  console.log(`[wallet] credential_imported id=${id}`);
};

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
