import path from "node:path";
import { spawn } from "node:child_process";

const repoRoot = path.resolve(process.cwd(), "..", "..");
const composeFile = path.join(repoRoot, "docker-compose.prod.yml");

type GuardCase = {
  name: string;
  service: string;
  env: Record<string, string>;
  expectedLogIncludes: string[];
};

const runCompose = (input: GuardCase) =>
  new Promise<{ code: number | null; output: string }>((resolve, reject) => {
    const args = [
      "compose",
      "-f",
      composeFile,
      "up",
      "--build",
      "--abort-on-container-exit",
      "--exit-code-from",
      input.service,
      input.service
    ];
    const proc = spawn("docker", args, {
      env: { ...process.env, ...input.env },
      stdio: ["ignore", "pipe", "pipe"]
    });
    let output = "";
    proc.stdout?.on("data", (chunk) => {
      output += chunk.toString();
    });
    proc.stderr?.on("data", (chunk) => {
      output += chunk.toString();
    });
    proc.on("error", reject);
    proc.on("close", (code) => resolve({ code, output }));
  });

const downCompose = () =>
  new Promise<void>((resolve, reject) => {
    const proc = spawn("docker", ["compose", "-f", composeFile, "down", "-v"], {
      stdio: "inherit"
    });
    proc.on("error", reject);
    proc.on("close", () => resolve());
  });

const runCase = async (guard: GuardCase) => {
  try {
    const result = await runCompose(guard);
    const failed = result.code !== 0 && result.code !== null;
    const matched = guard.expectedLogIncludes.every((needle) => result.output.includes(needle));
    if (failed && matched) {
      console.log(`PASS ${guard.name}`);
      return true;
    }
    const excerpt = result.output.split("\n").slice(-40).join("\n");
    throw new Error(
      `unexpected_exit code=${result.code ?? "null"} matched=${matched} excerpt=${excerpt}`
    );
  } finally {
    await downCompose();
  }
};

const main = async () => {
  const cases: GuardCase[] = [
    {
      name: "production missing pseudonymizer pepper",
      service: "verifier-service",
      env: {
        NODE_ENV: "production",
        PSEUDONYMIZER_PEPPER: "",
        SERVICE_BIND_ADDRESS: "127.0.0.1"
      },
      expectedLogIncludes: ["pseudonymizer_pepper_missing"]
    },
    {
      name: "mainnet guard without ALLOW_MAINNET",
      service: "verifier-service",
      env: {
        NODE_ENV: "production",
        HEDERA_NETWORK: "mainnet",
        ALLOW_MAINNET: "false",
        SERVICE_BIND_ADDRESS: "127.0.0.1"
      },
      expectedLogIncludes: ["mainnet_not_allowed"]
    },
    {
      name: "missing service auth secret in production",
      service: "app-gateway",
      env: {
        NODE_ENV: "production",
        SERVICE_JWT_SECRET: "",
        SERVICE_BIND_ADDRESS: "127.0.0.1"
      },
      expectedLogIncludes: ["SERVICE_JWT_SECRET"]
    }
  ];

  const results = [];
  for (const guard of cases) {
    try {
      results.push(await runCase(guard));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`FAIL ${guard.name}: ${message}`);
      results.push(false);
    }
  }

  if (!results.every(Boolean)) {
    process.exit(1);
  }
};

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
