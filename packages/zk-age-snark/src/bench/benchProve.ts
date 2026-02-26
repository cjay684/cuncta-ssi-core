import path from "node:path";
import { readFile } from "node:fs/promises";
import { commitDobDaysPoseidon, proveAgeGteV1, randomField } from "../index.js";

const repoRoot = path.resolve(process.cwd(), "..", "..");
const artifactsDir = path.join(repoRoot, "packages", "zk-age-snark", "artifacts", "age_gte_v1");

const main = async () => {
  const wasmFile = path.join(artifactsDir, "age_gte_v1.wasm");
  const zkeyFile = path.join(artifactsDir, "age_gte_v1.zkey");
  await readFile(wasmFile);
  await readFile(zkeyFile);

  const birthdateDays = Math.floor(Date.now() / 86_400_000) - 20 * 365;
  const rand = randomField();
  const commitment = await commitDobDaysPoseidon({ birthdateDays, rand });
  const currentDay = Math.floor(Date.now() / 86_400_000);
  const minAge = 18;
  const res = await proveAgeGteV1({
    birthdateDays,
    rand,
    dobCommitment: commitment,
    minAge,
    currentDay,
    nonce: "nonce-test-0123456789",
    audience: "origin:https://bench.local",
    requestHash: "deadbeef".repeat(8),
    wasmFile,
    zkeyFile
  });
  console.log(JSON.stringify({ proveMs: res.proveMs }, null, 2));
};

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

