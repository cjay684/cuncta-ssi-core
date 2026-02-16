import { spawnSync } from "node:child_process";

const thresholds = {
  lines: Number(process.env.COVERAGE_LINES ?? 50),
  branches: Number(process.env.COVERAGE_BRANCHES ?? 40),
  functions: Number(process.env.COVERAGE_FUNCTIONS ?? 40),
  statements: Number(process.env.COVERAGE_STATEMENTS ?? 50)
};

const args = [
  "--reporter",
  "text",
  "--reporter",
  "lcov",
  "--reporter",
  "html",
  "--check-coverage",
  "--lines",
  String(thresholds.lines),
  "--branches",
  String(thresholds.branches),
  "--functions",
  String(thresholds.functions),
  "--statements",
  String(thresholds.statements),
  "pnpm",
  "-r",
  "--workspace-concurrency=1",
  "test"
];

const result = spawnSync("c8", args, { stdio: "inherit", shell: true });
process.exit(result.status ?? 1);
