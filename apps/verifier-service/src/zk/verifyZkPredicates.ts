import { decodeJwt } from "jose";
import { z } from "zod";
import { getZkStatement } from "@cuncta/zk-registry";
import { readFile } from "node:fs/promises";
import { sha256ToField, verifyGroth16 } from "@cuncta/zk-proof-groth16-bn254";
import { createHash } from "node:crypto";
import { config } from "../config.js";

const zkProofEntrySchema = z.object({
  statement_id: z.string().min(1),
  version: z.string().min(1).optional(),
  proof_system: z.string().min(1).optional(),
  proof: z.unknown(),
  public_signals: z.array(z.string().min(1)),
  params: z.record(z.string(), z.unknown()).optional(),
  credential_vct: z.string().min(1).optional(),
  bindings: z
    .object({
      nonce: z.string().min(1),
      audience: z.string().min(1),
      request_hash: z.string().min(8)
    })
    .optional()
});

export const verifyRequiredZkPredicates = async (input: {
  requiredPredicates: Array<{ id: string; params?: Record<string, unknown> }>;
  zkProofs: unknown;
  requestHash: string;
  nonce: string;
  audience: string;
  requestJwt?: string;
  // Disclosed claim values from SD-JWT VC presentation.
  claims: Record<string, unknown>;
  expectedVct?: string;
}) => {
  const parsed = Array.isArray(input.zkProofs) ? input.zkProofs : [];
  const entries = parsed
    .map((e) => zkProofEntrySchema.safeParse(e))
    .filter((r) => r.success)
    .map((r) => r.data);

  const reasons: string[] = [];
  const deny = (r: string) => reasons.push(r);

  if (!input.requestJwt || input.requestJwt.length < 10) {
    return { ok: false, reasons: ["request_jwt_required"] };
  }
  const requestJwtPayload = decodeJwt(input.requestJwt) as Record<string, unknown>;
  const computedRequestHash = createHash("sha256").update(input.requestJwt).digest("hex");
  if (computedRequestHash !== input.requestHash) {
    deny("request_hash_mismatch");
  }
  const zkContext = (requestJwtPayload.zk_context as Record<string, unknown> | undefined) ?? {};
  const serverDay = Math.floor(Date.now() / 86_400_000);
  const maxDayDrift = config.VERIFIER_ZK_MAX_DAY_DRIFT_DAYS;

  for (const req of input.requiredPredicates) {
    const reasonsBeforeStatement = reasons.length;
    const statementId = String(req.id ?? "");
    const proof = entries.find((e) => e.statement_id === statementId);
    if (!proof) {
      deny("zk_proof_missing");
      continue;
    }

    let statement;
    try {
      statement = await getZkStatement(statementId);
    } catch (err) {
      const message = err instanceof Error ? err.message : "zk_statement_not_found";
      // Fail closed if the registry is present but hash-locked artifacts don't match.
      if (String(message).startsWith("zk_registry_hash_mismatch")) {
        deny("zk_registry_invalid");
      } else {
        deny("zk_statement_not_found");
      }
      continue;
    }
    if (!statement.available) {
      deny("zk_statement_unavailable");
      continue;
    }
    if (config.HEDERA_NETWORK === "mainnet" && config.ALLOW_EXPERIMENTAL_ZK) {
      const prov = statement.definition.setup_provenance ?? "unknown";
      if (prov !== "ceremony_attested") {
        deny("zk_setup_not_allowed_on_mainnet");
        continue;
      }
    }

    if (proof.proof_system && proof.proof_system !== statement.definition.proof_system) {
      deny("zk_proof_system_mismatch");
      continue;
    }
    if (proof.version && proof.version !== statement.definition.version) {
      deny("zk_statement_version_mismatch");
      continue;
    }

    if (input.expectedVct && statement.definition.credential.vct !== input.expectedVct) {
      deny("zk_credential_mismatch");
      continue;
    }

    // Map publicSignals[] to named fields.
    const order = statement.definition.public_inputs_order ?? [];
    if (!order.length) {
      deny("zk_public_inputs_order_missing");
      continue;
    }
    if (new Set(order).size !== order.length) {
      deny("zk_public_inputs_order_invalid");
      continue;
    }
    if (order.length !== proof.public_signals.length) {
      deny("zk_public_signals_invalid");
      continue;
    }
    const required = statement.definition.public_inputs_schema.required ?? [];
    for (const key of required) {
      if (!order.includes(key)) {
        deny("zk_public_inputs_missing");
      }
    }
    const pub: Record<string, string> = {};
    for (let i = 0; i < order.length; i += 1) {
      pub[order[i]!] = proof.public_signals[i]!;
    }

    // Enforce request binding *even if* proof verifies (names are registry-driven).
    const bindingInputs = statement.definition.verifier_contract.binding_public_inputs;
    for (const binding of statement.definition.required_bindings) {
      const pubKey =
        binding === "nonce"
          ? bindingInputs.nonce
          : binding === "audience"
            ? bindingInputs.audience
            : bindingInputs.request_hash;
      if (!pubKey || typeof pub[pubKey] !== "string") {
        deny("zk_public_inputs_missing");
        continue;
      }
      const expected =
        binding === "nonce"
          ? sha256ToField(input.nonce).toString()
          : binding === "audience"
            ? sha256ToField(input.audience).toString()
            : sha256ToField(input.requestHash).toString();
      if (pub[pubKey] !== expected) {
        deny(
          binding === "nonce"
            ? "nonce_mismatch"
            : binding === "audience"
              ? "aud_mismatch"
              : "request_hash_mismatch"
        );
      }
    }

    // Param constraints: policy params must match the statement's declared public inputs.
    const policyParams = req.params ?? {};
    for (const c of statement.definition.verifier_contract.param_constraints) {
      if (c.op !== "eq") continue;
      const policyValue = policyParams[c.param];
      if (typeof policyValue === "undefined") {
        deny("zk_param_missing");
        continue;
      }
      const pubValue = pub[c.public_input];
      if (typeof pubValue === "undefined") {
        deny("zk_public_inputs_missing");
        continue;
      }
      if (pubValue !== String(policyValue)) {
        deny("zk_param_mismatch");
      }
    }

    // Context constraints: signed request `zk_context` keys must match public inputs.
    for (const c of statement.definition.verifier_contract.context_constraints) {
      if (c.op !== "eq") continue;
      const ctxValue = zkContext[c.context_key];
      if (typeof ctxValue === "undefined") {
        deny("zk_context_required");
        continue;
      }
      const pubValue = pub[c.public_input];
      if (typeof pubValue === "undefined") {
        deny("zk_public_inputs_missing");
        continue;
      }
      if (pubValue !== String(ctxValue)) {
        deny("zk_context_mismatch");
      }
    }

    // Special hardening: if a statement requires `current_day`, enforce drift bounds vs verifier time.
    if (statement.definition.zk_context_requirements.current_day?.required) {
      const currentDay = Number(zkContext.current_day ?? NaN);
      if (!Number.isInteger(currentDay)) {
        deny("zk_context_current_day_missing");
      } else if (Math.abs(currentDay - serverDay) > maxDayDrift) {
        deny("zk_day_drift");
      }
    }

    // Required disclosures: ensure credential carrier discloses the required fields.
    for (const field of statement.definition.credential.required_disclosures ?? []) {
      if (typeof input.claims[field] === "undefined") {
        deny("required_disclosure_missing");
      }
    }

    // Credential linkage: commitment fields must be disclosed; if the statement exposes them as public inputs, enforce equality.
    for (const field of statement.definition.credential_requirements.required_commitment_fields) {
      const disclosed = input.claims[field];
      if (typeof disclosed === "undefined") {
        deny("required_disclosure_missing");
        continue;
      }
      if (typeof pub[field] !== "undefined" && pub[field] !== String(disclosed)) {
        deny("zk_commitment_mismatch");
      }
    }
    const allowedSchemes =
      statement.definition.credential_requirements.commitment_scheme_versions_allowed;
    if (allowedSchemes && allowedSchemes.length) {
      const scheme = String(input.claims.commitment_scheme_version ?? "");
      if (!allowedSchemes.includes(scheme)) {
        deny("commitment_scheme_mismatch");
      }
    }

    // If any earlier check already denied this statement, skip the expensive crypto verify step.
    // (We still fail closed overall; we just avoid doing unnecessary work.)
    if (reasons.length > reasonsBeforeStatement) {
      continue;
    }

    // Cryptographic verification using the statement's verifying key.
    const vkRaw = await readFile(statement.verifyingKeyPath, "utf8").catch(() => "");
    if (!vkRaw) {
      deny("zk_verifying_key_missing");
      continue;
    }
    let vkJson: unknown;
    try {
      vkJson = JSON.parse(vkRaw) as unknown;
    } catch {
      deny("zk_verifying_key_invalid");
      continue;
    }
    if (statement.definition.proof_system !== "groth16_bn254") {
      deny("zk_proof_system_unsupported");
      continue;
    }
    const ok = await verifyGroth16({
      verificationKey: vkJson,
      proof: proof.proof,
      publicSignals: proof.public_signals
    }).catch(() => ({ ok: false }));
    if (!ok.ok) {
      deny("zk_proof_invalid");
    }
  }

  return { ok: reasons.length === 0, reasons };
};
