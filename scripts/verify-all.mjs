import { spawnSync } from "node:child_process";

const run = (command, args) => {
  const result = spawnSync(command, args, { stdio: "inherit", shell: true });
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
};

run("pnpm", ["-r", "build"]);
run("pnpm", ["-r", "typecheck"]);
run("pnpm", ["-r", "--workspace-concurrency=1", "test"]);

if (process.env.RUN_TESTNET_INTEGRATION === "1") {
  run("pnpm", ["verify:testnet"]);
} else {
  console.log("Skipping Testnet integration (set RUN_TESTNET_INTEGRATION=1 to run).");
}
