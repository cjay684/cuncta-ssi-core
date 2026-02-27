import { z } from "zod";
import { createRemoteJWKSet, jwtVerify, decodeJwt } from "jose";
import { presentSdJwtVc } from "@cuncta/sdjwt";
import { Oid4vpRequestObjectSchema, canonicalizeJson } from "@cuncta/shared";
import { deriveDiBbsPresentation } from "@cuncta/di-bbs";
import { getZkStatement } from "@cuncta/zk-registry";
import { fullProveGroth16 } from "@cuncta/zk-proof-groth16-bn254";
import { getWalletWitnessBuilder } from "../zk/witnessBuilders/index.js";
import { sha256Base64Url } from "../crypto/sha256.js";
import { loadWalletState, saveWalletState } from "../walletStore.js";
import { randomUUID, createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { buildHolderJwtEdDsa, ensureHolderPublicJwk } from "../holder/holderKeys.js";

const toOptionalString = (value: unknown) => {
  if (value === undefined || value === null) return undefined;
  const trimmed = String(value).trim();
  return trimmed.length ? trimmed : undefined;
};

const envSchema = z.object({
  APP_GATEWAY_BASE_URL: z.string().url(),
  ISSUER_SERVICE_BASE_URL: z.string().url().optional(),
  ISSUER_BBS_PUBLIC_KEY_B64U: z.string().optional(),
  WALLET_VERIFY_REQUEST_SIGNATURE: z.preprocess((v) => v !== "false", z.boolean()).default(true),
  BREAK_GLASS_DISABLE_STRICT: z.preprocess((v) => v === "true", z.boolean()).default(false),
  NODE_ENV: z.string().optional(),
  HEDERA_NETWORK: z.enum(["testnet", "previewnet", "mainnet"]).optional()
});

const sha256Hex = (value: string) => createHash("sha256").update(value).digest("hex");
const toBytes = (hex: string) => Uint8Array.from(Buffer.from(hex, "hex"));

const resolveRequestJwtJwksUrl = (requestJwt: string, options: { strict: boolean }) => {
  const unverified = decodeJwt(requestJwt) as { iss?: string };
  const issRaw = typeof unverified.iss === "string" ? unverified.iss.trim() : "";
  if (!issRaw) {
    if (options.strict) {
      throw new Error("request_jwt_issuer_missing");
    }
    return "";
  }
  try {
    new URL(issRaw);
  } catch {
    if (options.strict) {
      throw new Error("request_jwt_issuer_invalid");
    }
    return "";
  }
  return `${issRaw.replace(/\/$/, "")}/.well-known/jwks.json`;
};

const argsSchema = z.object({
  request: z.string().min(1),
  credentialVct: z.string().min(1).optional(),
  emitResponseJwt: z.boolean().optional()
});

const parseArgs = () => {
  const args = process.argv.slice(3);
  const getArg = (name: string) => {
    const index = args.findIndex((arg) => arg === name);
    if (index === -1) return undefined;
    return args[index + 1];
  };
  const request = getArg("--request") ?? "";
  const credentialVct = getArg("--credential-vct");
  const emitResponseJwt = args.includes("--emit-response-jwt");
  return argsSchema.parse({ request, credentialVct, emitResponseJwt });
};

const resolveRequestArg = async (raw: string): Promise<string> => {
  const trimmed = raw.trim();
  if (!trimmed.startsWith("@")) return trimmed;
  const filePath = trimmed.slice(1).trim();
  if (!filePath) throw new Error("request_file_path_missing");
  return await readFile(filePath, "utf8");
};

const fetchJson = async <T>(url: string, init?: RequestInit): Promise<T> => {
  const res = await fetch(url, init);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`http_${res.status}: ${text}`);
  }
  return (await res.json()) as T;
};

const fetchText = async (url: string, init?: RequestInit): Promise<string> => {
  const res = await fetch(url, init);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`http_${res.status}: ${text}`);
  }
  return await res.text();
};

const stageTimeoutMs = (name: string) => {
  const key = `WALLET_VP_STAGE_TIMEOUT_${name.toUpperCase().replace(/[^A-Z0-9]+/g, "_")}_MS`;
  const raw = process.env[key];
  const parsed = Number(raw);
  if (Number.isFinite(parsed) && parsed > 0) return parsed;
  if (name === "zk.prove") return 45_000;
  if (name === "zk.witness") return 20_000;
  if (name === "zk.artifacts") return 10_000;
  // direct_post.jwt can exceed 10s under transient verifier/policy latency in CI/testnet.
  if (name === "response.post") return 30_000;
  return 10_000;
};

const withStageTimeout = async <T>(stage: string, fn: () => Promise<T>): Promise<T> => {
  const timeoutMs = stageTimeoutMs(stage);
  let timer: NodeJS.Timeout | null = null;
  try {
    return await Promise.race([
      fn(),
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => {
          reject(new Error(`vp_respond_timeout:${stage}:${timeoutMs}ms`));
        }, timeoutMs);
        timer.unref?.();
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
};

export const vpRespond = async () => {
  const commandStarted = Date.now();
  process.stdout.write("stage=vp.respond|event=start|elapsedMs=0\n");
  const commandHeartbeat = setInterval(() => {
    console.log(`stage=vp.respond|event=heartbeat|elapsedMs=${Date.now() - commandStarted}`);
  }, 5000);
  commandHeartbeat.unref?.();
  let checkpoint = "init";
  const logStage = (
    substage: string,
    event: "start" | "done",
    detail?: Record<string, unknown>
  ) => {
    if (event === "start") checkpoint = substage;
    const payload = {
      stage: "vp.respond",
      substage,
      event,
      ...(detail ?? {})
    };
    console.log(
      `stage=vp.respond|substage=${substage}|event=${event}|payload=${JSON.stringify(payload)}`
    );
  };
  const failWithCheckpoint = (error: unknown): never => {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`vp_respond_failed_at:${checkpoint}:${detail}`);
  };

  try {
    const env = envSchema.parse(process.env);
    logStage("parse.args", "start");
    const args = await withStageTimeout("parse.args", async () => parseArgs());
    logStage("parse.args", "done");

    logStage("wallet.load_state", "start");
    const state = await withStageTimeout("wallet.load_state", async () => loadWalletState());
    logStage("wallet.load_state", "done");

    logStage("wallet.resolve_holder_key", "start");
    const holderPublicJwk = await withStageTimeout("wallet.resolve_holder_key", async () =>
      ensureHolderPublicJwk()
    );
    logStage("wallet.resolve_holder_key", "done");

    logStage("request.parse_input", "start");
    const requestInput = await withStageTimeout("request.resolve_arg", async () =>
      resolveRequestArg(args.request)
    );
    const requestObj =
      requestInput.trim().startsWith("http://") || requestInput.trim().startsWith("https://")
        ? await withStageTimeout("request.fetch", async () =>
            fetchJson<unknown>(requestInput.trim())
          )
        : (JSON.parse(requestInput) as unknown);
    logStage("request.parse_input", "done");

    logStage("request.schema_validate", "start");
    const req = Oid4vpRequestObjectSchema.parse(requestObj);
    logStage("request.schema_validate", "done");
    if (!req) {
      throw new Error("oid4vp_request_schema_invalid:empty_request");
    }

    const strictRequestSignature =
      !env.BREAK_GLASS_DISABLE_STRICT && env.WALLET_VERIFY_REQUEST_SIGNATURE;

    const requestJwt = req.request_uri
      ? (
          await withStageTimeout("request.fetch_jwt_uri", async () =>
            fetchText(String(req.request_uri))
          )
        ).trim()
      : (req.request_jwt ?? "");

    if (requestJwt) {
      const jwksUrl = resolveRequestJwtJwksUrl(requestJwt, { strict: strictRequestSignature });
      if (jwksUrl) {
        try {
          const JWKS = createRemoteJWKSet(new URL(jwksUrl));
          logStage("request.verify_signature", "start");
          await withStageTimeout("request.verify_signature", async () =>
            jwtVerify(requestJwt, JWKS, {
              algorithms: ["EdDSA"],
              typ: "oid4vp-request+jwt"
            })
          );
          logStage("request.verify_signature", "done");
        } catch (err) {
          throw new Error(
            `request_signature_verification_failed:${err instanceof Error ? err.message : "unknown"}`
          );
        }
      }
    } else if (strictRequestSignature) {
      throw new Error("request_jwt_missing_strict_mode");
    }

    const requestJwtPayload = requestJwt ? (decodeJwt(requestJwt) as Record<string, unknown>) : {};
    const canonicalNonce =
      typeof requestJwtPayload.nonce === "string" ? requestJwtPayload.nonce : req.nonce;
    const canonicalAudience =
      typeof requestJwtPayload.audience === "string" ? requestJwtPayload.audience : req.audience;
    const canonicalAction =
      typeof requestJwtPayload.action_id === "string" ? requestJwtPayload.action_id : req.action;
    const responseUri =
      typeof requestJwtPayload.response_uri === "string"
        ? requestJwtPayload.response_uri
        : new URL("/oid4vp/response", env.APP_GATEWAY_BASE_URL).toString();
    const stateValue =
      typeof requestJwtPayload.state === "string" ? requestJwtPayload.state : req.state;
    const presentationDefinition =
      (requestJwtPayload.presentation_definition as Record<string, unknown> | undefined) ??
      (req.presentation_definition as unknown as Record<string, unknown>);

    const vct =
      toOptionalString(args.credentialVct) ??
      req.requirements[0]?.vct ??
      (() => {
        throw new Error("request_missing_requirement");
      })();
    const requirement = req.requirements.find((r) => r.vct === vct);
    const disclosures = new Set<string>(requirement?.disclosures ?? []);
    for (const predicate of requirement?.predicates ?? []) {
      disclosures.add(predicate.path);
    }

    const requirementExtras = requirement as unknown as {
      formats?: unknown;
      zk_predicates?: unknown;
    };
    const allowedFormats = Array.isArray(requirementExtras.formats)
      ? requirementExtras.formats.map(String)
      : ["dc+sd-jwt"];
    const preferDi = process.env.WALLET_PREFER_DI_BBS === "1";
    const hasSd = (state.credentials ?? []).some(
      (c: { vct?: unknown; format?: unknown }) =>
        String(c.vct ?? "") === vct && String(c.format ?? "dc+sd-jwt") === "dc+sd-jwt"
    );
    const hasDi = (state.credentials ?? []).some(
      (c: { vct?: unknown; format?: unknown }) =>
        String(c.vct ?? "") === vct && String(c.format ?? "") === "di+bbs"
    );
    const allowSd = allowedFormats.includes("dc+sd-jwt");
    const allowDi = allowedFormats.includes("di+bbs");
    const chosenFormat: "dc+sd-jwt" | "di+bbs" = preferDi
      ? allowDi && hasDi
        ? "di+bbs"
        : allowSd
          ? "dc+sd-jwt"
          : "di+bbs"
      : allowSd && hasSd
        ? "dc+sd-jwt"
        : allowDi && hasDi
          ? "di+bbs"
          : allowSd
            ? "dc+sd-jwt"
            : "di+bbs";

    const requestHash = requestJwt ? sha256Hex(requestJwt) : "";
    if (!requestHash) {
      throw new Error("request_hash_missing");
    }

    const nowSeconds = Math.floor(Date.now() / 1000);
    const expSeconds = Math.max(nowSeconds + 30, Math.floor(Date.parse(req.expires_at) / 1000));

    let vpToken: string = "";
    let descriptorFormat: string = "sd-jwt-vc";
    let zkProofs: unknown[] | undefined = undefined;

    if (chosenFormat === "dc+sd-jwt") {
      logStage("credential.select_sdjwt", "start", { vct });
      const zkPredicatesRaw = Array.isArray(requirementExtras.zk_predicates)
        ? requirementExtras.zk_predicates
        : [];
      const resolvedZkPredicates: Array<{
        pred: { id: string; params: Record<string, unknown> };
        statement: Awaited<ReturnType<typeof getZkStatement>>;
      }> = [];
      for (const p of zkPredicatesRaw) {
        const pred = (p ?? {}) as { id?: unknown; params?: unknown };
        const statementId = String(pred.id ?? "").trim();
        if (!statementId) throw new Error("zk_statement_id_missing");
        const statement = await getZkStatement(statementId);
        if (!statement.available) throw new Error(`zk_statement_unavailable:${statementId}`);
        if (statement.definition.credential.format !== "dc+sd-jwt") {
          throw new Error(
            `zk_credential_format_unsupported:${statement.definition.credential.format}`
          );
        }
        for (const field of statement.definition.credential.required_disclosures ?? []) {
          disclosures.add(field);
        }
        resolvedZkPredicates.push({
          pred: { id: statementId, params: (pred.params ?? {}) as Record<string, unknown> },
          statement
        });
      }

      const entry = (state.credentials ?? []).find(
        (c: { vct?: unknown; format?: unknown }) =>
          String(c.vct ?? "") === vct && String(c.format ?? "dc+sd-jwt") === "dc+sd-jwt"
      );
      const credential = entry?.credential as string | undefined;
      if (!credential || typeof credential !== "string")
        throw new Error(`credential_missing:${vct}`);
      logStage("credential.select_sdjwt", "done", {
        hasZkPredicates: resolvedZkPredicates.length > 0
      });

      logStage("sdjwt.build_disclosures", "start");
      const sdJwtPresentation = await withStageTimeout("sdjwt.build_disclosures", async () =>
        presentSdJwtVc({
          sdJwt: credential,
          disclose: Array.from(disclosures)
        })
      );
      logStage("sdjwt.build_disclosures", "done");

      logStage("kbjwt.build", "start");
      const kbJwt = await withStageTimeout("kbjwt.build", async () =>
        buildHolderJwtEdDsa({
          header: { alg: "EdDSA", typ: "kb+jwt" },
          payload: {
            aud: canonicalAudience,
            nonce: canonicalNonce,
            iat: nowSeconds,
            exp: expSeconds,
            sd_hash: sha256Base64Url(sdJwtPresentation),
            cnf: { jwk: { kty: "OKP", crv: "Ed25519", x: holderPublicJwk.x, alg: "EdDSA" } }
          }
        })
      );
      logStage("kbjwt.build", "done");

      vpToken = `${sdJwtPresentation}${kbJwt}`;
      descriptorFormat = "sd-jwt-vc";
      state.lastPresentation = {
        action: canonicalAction,
        presentation: vpToken,
        nonce: canonicalNonce,
        audience: canonicalAudience
      };
      await saveWalletState(state);

      // Continue with response JWT below using vpToken.
      // (falls through)

      if (resolvedZkPredicates.length > 0) {
        const requestZkContext =
          (requestJwtPayload.zk_context as Record<string, unknown> | undefined) ?? {};

        const proofs: unknown[] = [];
        for (const item of resolvedZkPredicates) {
          logStage("zk.predicate.begin", "start", {
            statementId: item.statement.definition.statement_id
          });
          const statement = item.statement;
          const stateWithSecrets = state as unknown as {
            zkSecrets?: Record<string, Record<string, unknown>>;
          };
          const secretBucketKey = statement.definition.credential.credential_config_id;
          const secrets = stateWithSecrets.zkSecrets?.[secretBucketKey] ?? null;
          if (!secrets) {
            throw new Error(`zk_secrets_missing:${secretBucketKey}`);
          }

          const disclosedClaims: Record<string, unknown> = {};
          for (const field of statement.definition.credential.required_disclosures ?? []) {
            disclosedClaims[field] = secrets[field];
          }

          const witnessBuilder = getWalletWitnessBuilder(
            statement.definition.wallet_contract.witness_builder_id
          );
          if (!witnessBuilder) {
            throw new Error(
              `zk_witness_builder_missing:${statement.definition.wallet_contract.witness_builder_id}`
            );
          }

          // Registry-driven: `zk_context` must come from the signed request JWT, not from the RP surface.
          if (statement.definition.zk_context_requirements.current_day?.required) {
            if (!Number.isInteger(Number(requestZkContext.current_day ?? NaN))) {
              throw new Error("zk_context_current_day_missing");
            }
          }

          logStage("zk.witness", "start", {
            statementId: statement.definition.statement_id
          });
          const witness = await withStageTimeout("zk.witness", async () =>
            witnessBuilder({
              statementId: statement.definition.statement_id,
              circuitId: statement.definition.circuit_id,
              params: item.pred.params,
              zkContext: requestZkContext,
              bindings: { nonce: canonicalNonce, audience: canonicalAudience, requestHash },
              disclosedClaims,
              secrets
            })
          );
          logStage("zk.witness", "done", {
            statementId: statement.definition.statement_id
          });

          const wasmFile = statement.wasmPath;
          const zkeyFile = statement.provingKeyPath;
          if (!wasmFile) throw new Error("zk_wasm_missing");
          logStage("zk.artifacts", "start", { wasmFile, zkeyFile });
          const [wasmStat, zkeyStat] = await withStageTimeout("zk.artifacts", async () =>
            Promise.all([stat(wasmFile), stat(zkeyFile)])
          );
          logStage("zk.artifacts", "done", {
            wasmBytes: wasmStat.size,
            zkeyBytes: zkeyStat.size
          });

          if (statement.definition.proof_system !== "groth16_bn254") {
            throw new Error(`zk_proof_system_unsupported:${statement.definition.proof_system}`);
          }
          logStage("zk.prove", "start", { statementId: statement.definition.statement_id });
          const proofRes = await withStageTimeout("zk.prove", async () =>
            fullProveGroth16({ witness, wasmFile, zkeyFile })
          );
          logStage("zk.prove", "done", {
            statementId: statement.definition.statement_id,
            publicSignals: Array.isArray(proofRes.publicSignals) ? proofRes.publicSignals.length : 0
          });

          proofs.push({
            statement_id: statement.definition.statement_id,
            version: statement.definition.version,
            proof_system: statement.definition.proof_system,
            params: item.pred.params,
            public_signals: proofRes.publicSignals,
            proof: proofRes.proof,
            credential_vct: vct,
            // Explicit bindings (verifier also checks these match request and public signals)
            bindings: {
              nonce: canonicalNonce,
              audience: canonicalAudience,
              request_hash: requestHash
            }
          });
        }
        zkProofs = proofs;
        logStage("zk.predicate.begin", "done", { proofs: proofs.length });
      }
    } else if (chosenFormat === "di+bbs") {
      const entry = (state.credentials ?? []).find(
        (c: { vct?: unknown; format?: unknown }) =>
          String(c.vct ?? "") === vct && String(c.format ?? "") === "di+bbs"
      );
      type DiCredential = Parameters<typeof deriveDiBbsPresentation>[0]["credential"];
      const diVc = entry?.credential as unknown as DiCredential;
      if (!diVc || typeof diVc !== "object") throw new Error(`credential_missing:${vct}:di`);
      const entryWithIssuerKey = entry as { issuerBbsPublicKeyB64u?: unknown } | undefined;
      const fromEntry =
        entryWithIssuerKey && typeof entryWithIssuerKey.issuerBbsPublicKeyB64u === "string"
          ? String(entryWithIssuerKey.issuerBbsPublicKeyB64u)
          : "";
      const pkB64u = (env.ISSUER_BBS_PUBLIC_KEY_B64U ?? "").trim() || fromEntry;
      if (!pkB64u) throw new Error("issuer_bbs_public_key_missing");
      const publicKey = Uint8Array.from(Buffer.from(pkB64u, "base64url"));

      const bbsNonce = toBytes(sha256Hex(`${canonicalAudience}|${canonicalNonce}|${requestHash}`));
      logStage("di_bbs.derive", "start");
      const derived = await withStageTimeout("di_bbs.derive", async () =>
        deriveDiBbsPresentation({
          credential: diVc,
          publicKey,
          revealPaths: Array.from(disclosures),
          nonce: bbsNonce
        })
      );
      logStage("di_bbs.derive", "done");

      const bindingPayload = {
        format: "di+bbs",
        request_hash: requestHash,
        subject_did: String(state.did?.did ?? ""),
        credential: diVc,
        presentation: derived
      };
      logStage("kbjwt.build", "start");
      const kbJwt = await withStageTimeout("kbjwt.build", async () =>
        buildHolderJwtEdDsa({
          header: { alg: "EdDSA", typ: "kb+jwt" },
          payload: {
            aud: canonicalAudience,
            nonce: canonicalNonce,
            iat: nowSeconds,
            exp: expSeconds,
            sd_hash: sha256Base64Url(canonicalizeJson(bindingPayload)),
            cnf: { jwk: { kty: "OKP", crv: "Ed25519", x: holderPublicJwk.x, alg: "EdDSA" } }
          }
        })
      );
      logStage("kbjwt.build", "done");

      vpToken = JSON.stringify({ ...bindingPayload, kb_jwt: kbJwt });
      descriptorFormat = "di+bbs";
    }
    if (!vpToken) throw new Error("vp_token_missing");

    // Standards path: response_mode=direct_post.jwt
    // We sign a response JWT with the holder key and POST it as form-encoded `response=...`.
    const pd = presentationDefinition as unknown as {
      input_descriptors?: Array<{ id?: unknown }>;
      id?: unknown;
    };
    const inputDescriptorId = String(
      pd?.input_descriptors?.[0]?.id ?? req.requirements[0]?.vct ?? vct
    );
    const submission = {
      id: `ps_${randomUUID()}`,
      definition_id: String(pd?.id ?? `cuncta:${canonicalAction}`),
      descriptor_map: [
        {
          id: inputDescriptorId,
          format: descriptorFormat,
          path: "$.vp_token"
        }
      ]
    };

    logStage("response.jwt.build", "start");
    const responseJwt = await withStageTimeout("response.jwt.build", async () =>
      buildHolderJwtEdDsa({
        header: { alg: "EdDSA", typ: "oauth-authz-res+jwt" },
        payload: {
          vp_token: vpToken,
          presentation_submission: submission,
          state: stateValue,
          request: requestJwt,
          ...(zkProofs ? { zk_proofs: zkProofs } : {}),
          aud: responseUri,
          iat: nowSeconds,
          exp: expSeconds,
          jti: randomUUID(),
          cnf: { jwk: { kty: "OKP", crv: "Ed25519", x: holderPublicJwk.x, alg: "EdDSA" } }
        }
      })
    );
    logStage("response.jwt.build", "done");

    if (args.emitResponseJwt) {
      // Test harness / debugging only. Do not enable in production scripts.
      console.log(JSON.stringify({ response_jwt: responseJwt }));
      return;
    }

    logStage("response.post", "start", { responseUri });
    const response = await withStageTimeout("response.post", async () =>
      fetch(responseUri, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ response: responseJwt }).toString()
      })
    );
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`oid4vp_response_failed:${text}`);
    }
    const verify = (await response.json()) as unknown;
    logStage("response.post", "done");

    // Single-line JSON so the integration harness can reliably parse stdout.
    const verifyRecord =
      verify && typeof verify === "object"
        ? (verify as Record<string, unknown>)
        : ({} as Record<string, unknown>);
    console.log(
      JSON.stringify({
        event: "vp.respond.result",
        decision: verifyRecord.decision ?? null,
        reasons: verifyRecord.reasons ?? null
      })
    );
    logStage("done", "done");
    console.log(JSON.stringify(verify));
  } catch (error) {
    const errorDetail = error instanceof Error ? error.message : String(error);
    console.log(
      JSON.stringify({
        event: "vp.respond.result",
        decision: null,
        reasons: [errorDetail]
      })
    );
    if (error instanceof z.ZodError) {
      const issues = error.issues
        .map((issue) => `${issue.path.join(".") || "(root)"}:${issue.message}`)
        .join(",");
      throw new Error(`vp_respond_failed_at:${checkpoint}:oid4vp_request_schema_invalid:${issues}`);
    }
    failWithCheckpoint(error);
  } finally {
    clearInterval(commandHeartbeat);
  }
};
