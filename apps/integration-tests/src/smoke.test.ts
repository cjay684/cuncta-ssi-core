import { strict as assert } from "node:assert";
import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const run = async () => {
  // Offline/deterministic smoke: ensure the harness targets the intended public/admin surfaces.
  const runTsUrl = new URL("./run.ts", import.meta.url);
  const text = await readFile(runTsUrl, "utf8");

  // SSI-core: harness must target identity.verify action.
  assert.ok(text.includes("identity.verify"), "harness must target identity.verify action");

  // Customer readiness checklist (offline, deterministic):
  // - Example env must not enable break-glass / dev auth by default
  // - Production configs must fail closed if break-glass is enabled (even with otherwise-valid env)
  const repoRoot = new URL("../../..", import.meta.url);
  const envExamplePath = new URL("./.env.example", repoRoot);
  const envExample = await readFile(envExamplePath, "utf8").catch(() => "");
  assert.ok(envExample.length > 0, ".env.example must exist");
  const forbiddenDefaults = [
    "BREAK_GLASS_DISABLE_STRICT=true",
    "ALLOW_INSECURE_DEV_AUTH=true",
    "ALLOW_LEGACY_SERVICE_JWT_SECRET=true",
    "POLICY_SIGNING_BOOTSTRAP=true",
    "VERIFIER_SIGNING_BOOTSTRAP=true",
    "OID4VCI_TOKEN_SIGNING_BOOTSTRAP=true"
  ];
  for (const needle of forbiddenDefaults) {
    assert.ok(!envExample.includes(needle), `.env.example must not default-enable ${needle}`);
  }

  const runConfigImport = (input: {
    name: string;
    importPath: string;
    env: Record<string, string>;
    expectExitCode: number;
  }) => {
    const code = `import('${input.importPath}').then(()=>process.exit(0)).catch((e)=>{console.error(e?.message||String(e)); process.exit(1);});`;
    const res = spawnSync("node", ["--loader", "ts-node/esm", "-e", code], {
      cwd: fileURLToPath(repoRoot),
      env: { ...process.env, ...input.env },
      encoding: "utf8",
      shell: false
    });
    assert.equal(
      res.status ?? -1,
      input.expectExitCode,
      `${input.name} config import unexpected exit (status=${res.status}) stderr=${res.stderr}`
    );
  };

  const baseProdEnv = {
    NODE_ENV: "production",
    HEDERA_NETWORK: "testnet",
    ALLOW_MAINNET: "false",
    DATABASE_URL: "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi",
    PSEUDONYMIZER_PEPPER: "test-pepper-please-change",
    SERVICE_JWT_SECRET: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // >=43 base64url chars
    DID_SERVICE_BASE_URL: "http://localhost:3001",
    ISSUER_SERVICE_BASE_URL: "http://localhost:3002",
    VERIFIER_SERVICE_BASE_URL: "http://localhost:3003",
    POLICY_SERVICE_BASE_URL: "http://localhost:3004",
    ISSUER_BASE_URL: "http://localhost:3002"
  };

  // Import should succeed with strict flags OFF.
  runConfigImport({
    name: "app-gateway",
    importPath: "./apps/app-gateway/src/config.ts",
    env: { ...baseProdEnv, USER_PAYS_HANDOFF_SECRET: baseProdEnv.SERVICE_JWT_SECRET },
    expectExitCode: 0
  });
  runConfigImport({
    name: "policy-service",
    importPath: "./apps/policy-service/src/config.ts",
    env: baseProdEnv,
    expectExitCode: 0
  });
  runConfigImport({
    name: "verifier-service",
    importPath: "./apps/verifier-service/src/config.ts",
    env: {
      ...baseProdEnv,
      ISSUER_SERVICE_BASE_URL: "http://localhost:3002",
      // Keep request signing disabled for this smoke import (production requires a provisioned key).
      VERIFIER_SIGN_OID4VP_REQUEST: "false"
    },
    expectExitCode: 0
  });
  runConfigImport({
    name: "issuer-service",
    importPath: "./apps/issuer-service/src/config.ts",
    env: {
      ...baseProdEnv,
      // issuer-service requires an OID4VCI token signing key in production posture when enabled; leave disabled for smoke.
      ISSUER_ENABLE_OID4VCI: "false"
    },
    expectExitCode: 0
  });

  // Import must fail closed if break-glass is enabled.
  runConfigImport({
    name: "app-gateway break-glass",
    importPath: "./apps/app-gateway/src/config.ts",
    env: {
      ...baseProdEnv,
      USER_PAYS_HANDOFF_SECRET: baseProdEnv.SERVICE_JWT_SECRET,
      BREAK_GLASS_DISABLE_STRICT: "true",
      // Ensure the check isn't bypassed by mainnet guardrails.
      HEDERA_NETWORK: "testnet"
    },
    expectExitCode: 1
  });

  console.log("integration-tests smoke: ok");
};

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
