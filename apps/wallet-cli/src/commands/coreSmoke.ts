import { z } from "zod";
import { didCreate } from "./didCreate.js";
import { didResolve } from "./didResolve.js";
import { issueRequest } from "./issueRequest.js";
import { present } from "./present.js";
import { verify } from "./verify.js";
import { auraSimulate } from "./auraSimulate.js";
import { auraClaim } from "./auraClaim.js";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const envSchema = z.object({
  DID_SERVICE_BASE_URL: z.string().url(),
  ISSUER_SERVICE_BASE_URL: z.string().url(),
  VERIFIER_SERVICE_BASE_URL: z.string().url(),
  POLICY_SERVICE_BASE_URL: z.string().url()
});

type WalletState = {
  did?: { did?: string };
  credentials?: Array<{
    vct: string;
    eventId?: string;
    credentialFingerprint?: string;
  }>;
};

const walletStatePath = () => {
  const dir = path.dirname(fileURLToPath(import.meta.url));
  return path.join(dir, "..", "..", "wallet-state.json");
};

const loadWalletState = async (): Promise<WalletState> => {
  const content = await readFile(walletStatePath(), "utf8");
  return JSON.parse(content) as WalletState;
};

const revokeLatest = async (issuerBaseUrl: string, vct: string) => {
  const state = await loadWalletState();
  const credential = state.credentials?.find((entry) => entry.vct === vct);
  if (!credential) {
    throw new Error("credential_missing");
  }
  const response = await fetch(`${issuerBaseUrl}/v1/credentials/revoke`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      eventId: credential.eventId,
      credentialFingerprint: credential.credentialFingerprint
    })
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`revoke_failed: ${text}`);
  }
};

export const coreSmoke = async () => {
  const results: Array<{ step: string; ok: boolean; detail?: string }> = [];
  const devMode = process.env.DEV_MODE === "true";
  const env = envSchema.parse(process.env);
  const action = devMode ? "dev.aura.signal" : "marketplace.list_item";

  const runStep = async (step: string, fn: () => Promise<void>) => {
    try {
      await fn();
      results.push({ step, ok: true });
    } catch (error) {
      const message = error instanceof Error ? error.message : "unknown_error";
      results.push({ step, ok: false, detail: message });
      throw new Error(`${step}: ${message}`);
    }
  };

  await runStep("ensure_did", async () => {
    try {
      await didResolve();
    } catch {
      await didCreate();
      await didResolve();
    }
  });

  await runStep("issue_credential", async () => {
    await issueRequest();
  });

  if (devMode) {
    await runStep("requirements_dev_aura", async () => {
      const response = await fetch(
        `${env.POLICY_SERVICE_BASE_URL}/v1/requirements?action=dev.aura.signal`
      );
      if (!response.ok) {
        const text = await response.text();
        throw new Error(`requirements_failed: ${text}`);
      }
    });
  }

  await runStep("present_verify_allow", async () => {
    await present(action);
    const result = await verify(action);
    const payload = result as { decision?: string } | undefined;
    if (payload?.decision !== "ALLOW") {
      throw new Error(`verify_not_allowed: ${payload?.decision ?? "unknown"}`);
    }
  });

  if (devMode) {
    await runStep("aura_simulate", async () => {
      await auraSimulate(action, 2);
    });
    await runStep("aura_claim", async () => {
      await auraClaim("cuncta.marketplace.seller_good_standing");
    });
  }

  await runStep("revoke_and_verify_deny", async () => {
    await revokeLatest(env.ISSUER_SERVICE_BASE_URL, "cuncta.marketplace.seller_good_standing");
    await present(action);
    const result = await verify(action);
    const payload = result as { decision?: string } | undefined;
    if (payload?.decision !== "DENY") {
      throw new Error(`verify_not_denied: ${payload?.decision ?? "unknown"}`);
    }
  });

  const failed = results.find((entry) => !entry.ok);
  if (failed) {
    console.log(`FAIL core:smoke step=${failed.step} detail=${failed.detail ?? ""}`);
    process.exit(1);
  }
  console.log("PASS core:smoke");
};
