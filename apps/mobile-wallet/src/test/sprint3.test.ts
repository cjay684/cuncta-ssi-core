import { strict as assert } from "node:assert";
import path from "node:path";
import { rm } from "node:fs/promises";
import { createFileVault } from "../core/vault/fileVault.js";
import { loadConfig } from "../core/config.js";
import {
  applyDisclosureSelection,
  extractDisclosureOptions,
  deriveRequiredDisclosures,
  discloseAll
} from "../core/disclosure/index.js";
import {
  checkRelyingPartyStatus,
  rememberRelyingParty,
  formatRelyingPartyLog
} from "../core/relyingParty/index.js";

const run = async (name: string, fn: () => Promise<void>) => {
  try {
    await fn();
    console.log(`ok - ${name}`);
  } catch (error) {
    console.error(`not ok - ${name}`);
    console.error(error instanceof Error ? (error.stack ?? error.message) : error);
    process.exitCode = 1;
  }
};

const encodeDisclosure = (value: unknown[]) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

await run("disclosure selection filters presentation", async () => {
  const jwt = "header.payload.signature";
  const d1 = encodeDisclosure(["salt1", "age", 21]);
  const d2 = encodeDisclosure(["salt2", "email", "user@example.com"]);
  const sdJwt = `${jwt}~${d1}~${d2}~`;
  const options = extractDisclosureOptions(sdJwt);
  const selectedId = options.find((opt) => opt.label === "age")?.id;
  assert.ok(selectedId);
  const presentation = applyDisclosureSelection(sdJwt, [selectedId]);
  assert.ok(presentation.includes(d1));
  assert.ok(!presentation.includes(d2));
});

await run("disclose all matches full presentation", async () => {
  const jwt = "header.payload.signature";
  const d1 = encodeDisclosure(["salt1", "age", 21]);
  const d2 = encodeDisclosure(["salt2", "email", "user@example.com"]);
  const sdJwt = `${jwt}~${d1}~${d2}~`;
  const full = `${jwt}~${d1}~${d2}~`;
  const result = await discloseAll(sdJwt);
  assert.equal(result, full);
});

await run("derive required disclosures from requirements", async () => {
  const jwt = "header.payload.signature";
  const d1 = encodeDisclosure(["salt1", "age", 21]);
  const d2 = encodeDisclosure(["salt2", "email", "user@example.com"]);
  const sdJwt = `${jwt}~${d1}~${d2}~`;
  const options = extractDisclosureOptions(sdJwt);
  const required = deriveRequiredDisclosures({
    requirements: {
      requirements: [{ vct: "cuncta.age_over_18", disclosures: ["age"] }]
    },
    options,
    vct: "cuncta.age_over_18"
  });
  assert.equal(required.length, 1);
});

await run("derive required disclosures ambiguous last segment", async () => {
  const options = [
    { id: "a", label: "city", path: "address.city", disclosure: "d1" },
    { id: "b", label: "city", path: "employer.city", disclosure: "d2" }
  ];
  const required = deriveRequiredDisclosures({
    requirements: {
      requirements: [{ vct: "cuncta.profile", predicates: [{ path: "profile.city", op: "eq" }] }]
    },
    options,
    vct: "cuncta.profile"
  });
  assert.equal(required.length, 0);
});

await run("relying party first seen and hash change", async () => {
  process.env.NODE_ENV = "development";
  process.env.WALLET_BUILD_MODE = "development";
  process.env.WALLET_ALLOW_SOFTWARE_KEYS = "true";
  process.env.APP_GATEWAY_BASE_URL = "http://localhost:3010";
  process.env.WALLET_VAULT_KEY = "abababababababababababababababababababababababababababababababab";
  const config = loadConfig();
  const baseDir = path.resolve(process.cwd(), "apps", "mobile-wallet", ".tmp-test-6");
  const vault = createFileVault({ baseDir, keyMaterial: config.WALLET_VAULT_KEY });
  await vault.init();
  const status1 = await checkRelyingPartyStatus(vault, { aud: "cuncta.action:demo" });
  assert.equal(status1.firstSeen, true);
  await rememberRelyingParty(vault, {
    aud: "cuncta.action:demo",
    firstSeenAt: new Date().toISOString(),
    lastSeenAt: new Date().toISOString(),
    policyHash: "policy:1"
  });
  const status2 = await checkRelyingPartyStatus(vault, {
    aud: "cuncta.action:demo",
    policyHash: "policy:2"
  });
  assert.equal(status2.hashChanged, true);
  const raw = await import("node:fs/promises").then((m) =>
    m.readFile(path.join(baseDir, "wallet.vault.json"), "utf8")
  );
  assert.ok(!raw.includes("cuncta.action:demo"));
  await rm(baseDir, { recursive: true, force: true });
});

await run("relying party log omits raw aud", async () => {
  const audHash = "abc123";
  const logLine = formatRelyingPartyLog({
    audHash,
    firstSeen: true,
    policyChanged: false
  });
  assert.ok(!logLine.includes("verifier.example"));
  assert.ok(logLine.includes(audHash));
});
