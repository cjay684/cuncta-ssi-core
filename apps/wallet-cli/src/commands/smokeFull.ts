import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { z } from "zod";
import { didCreate } from "./didCreate.js";
import { didResolve } from "./didResolve.js";
import { vcIssueAge } from "./vcIssueAge.js";
import { presentAge } from "./presentAge.js";

const envSchema = z.object({
  ISSUER_SERVICE_BASE_URL: z.string().url(),
  VERIFIER_SERVICE_BASE_URL: z.string().url(),
  POLICY_SERVICE_BASE_URL: z.string().url()
});

type WalletState = {
  did?: {
    did?: string;
  };
};

const walletStatePath = () => {
  const dir = path.dirname(fileURLToPath(import.meta.url));
  return path.join(dir, "..", "..", "wallet-state.json");
};

const loadWalletState = async (): Promise<WalletState> => {
  const content = await readFile(walletStatePath(), "utf8");
  return JSON.parse(content) as WalletState;
};

const postJson = async <T>(url: string, body: unknown) => {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`${url} failed: ${text}`);
  }
  return (await response.json()) as T;
};

export const smokeFull = async () => {
  const env = envSchema.parse(process.env);
  let state: WalletState | null = null;
  try {
    state = await loadWalletState();
  } catch {
    state = null;
  }

  if (!state?.did?.did) {
    await didCreate();
    await didResolve();
    state = await loadWalletState();
  } else {
    await didResolve();
  }

  const subjectDid = state?.did?.did;
  if (!subjectDid) {
    throw new Error("holder_did_missing");
  }

  await vcIssueAge();
  const verifyOk = await presentAge();
  if (!verifyOk?.valid) {
    throw new Error("verify_failed_before_revoke");
  }

  const policyDecision = await postJson<{ requirements: unknown[] }>(
    `${env.POLICY_SERVICE_BASE_URL}/v1/policy/evaluate`,
    {
      subjectDid,
      action: "identity.verify",
      context: {}
    }
  );
  if (!policyDecision.requirements.length) {
    throw new Error("policy_requirements_missing");
  }

  console.log("PASS smoke:full");
};
