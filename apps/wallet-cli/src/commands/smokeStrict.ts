import { didCreate } from "./didCreate.js";
import { didResolve } from "./didResolve.js";
import { vcIssueAge } from "./vcIssueAge.js";
import { presentAge } from "./presentAge.js";
import { z } from "zod";
import { decodeJwt } from "jose";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const envSchema = z.object({
  ISSUER_SERVICE_BASE_URL: z.string().url()
});

const walletStatePath = () => {
  const dir = path.dirname(fileURLToPath(import.meta.url));
  return path.join(dir, "..", "..", "wallet-state.json");
};

const decodeJwtPayload = (token: string) => {
  const [jwt] = token.split("~");
  if (!jwt) {
    throw new Error("sd_jwt_invalid");
  }
  return decodeJwt(jwt) as Record<string, unknown>;
};

export const smokeStrict = async () => {
  try {
    await didResolve();
  } catch {
    await didCreate();
    await didResolve();
  }
  await vcIssueAge();
  const state = JSON.parse(await readFile(walletStatePath(), "utf8")) as {
    credentials?: Array<{ credentialId: string; vct: string; sdJwt?: string }>;
  };
  const issued = state.credentials?.find((cred) => cred.vct === "cuncta.age_over_18");
  if (!issued?.sdJwt) {
    throw new Error("credential_missing");
  }
  const payload = decodeJwtPayload(issued.sdJwt);
  const issuer = payload.iss;
  const subject = payload.sub;
  if (issuer && subject && issuer === subject) {
    console.error(
      JSON.stringify(
        { issuerDid: issuer, holderDid: subject, error: "issuer_equals_subject" },
        null,
        2
      )
    );
    throw new Error("INVALID SSI: issuer DID equals holder DID");
  }

  const before = await presentAge();
  if (!before?.valid) {
    throw new Error("verify_failed_before_revoke");
  }
  type VerifyResult = {
    valid?: boolean;
    claims?: Record<string, unknown>;
    diagnostics?: { sdjwt?: { disclosureCount?: number } };
  };
  const beforeResult = before as VerifyResult | undefined;
  const disclosureCount = beforeResult?.diagnostics?.sdjwt?.disclosureCount ?? 0;
  if (disclosureCount <= 0) {
    throw new Error("disclosure_missing");
  }
  const claims = beforeResult?.claims ?? {};
  if (!("age_over_18" in claims)) {
    throw new Error("required_claim_missing");
  }

  const env = envSchema.parse(process.env);
  const credentialId = issued.credentialId;
  const eventId = (issued as { eventId?: string }).eventId;
  const credentialFingerprint = (issued as { credentialFingerprint?: string })
    .credentialFingerprint;
  if (!credentialId && !eventId && !credentialFingerprint) {
    throw new Error("credential_id_missing");
  }
  let revokeResponse: Response;
  try {
    revokeResponse = await fetch(`${env.ISSUER_SERVICE_BASE_URL}/v1/credentials/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        credentialId,
        eventId,
        credentialFingerprint
      })
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "revoke_network_error";
    throw new Error(`revoke_failed: ${message}`);
  }
  if (!revokeResponse.ok) {
    const text = await revokeResponse.text();
    throw new Error(`revoke_failed: ${text}`);
  }

  const after = await presentAge();
  if (after?.valid) {
    throw new Error("verify_should_fail_after_revoke");
  }
  console.log("PASS smoke:strict");
};
