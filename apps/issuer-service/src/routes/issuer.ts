import { FastifyInstance } from "fastify";
import { z } from "zod";
import { config } from "../config.js";
import { log } from "../log.js";
import { issueCredentialCore } from "../core/issueCredential.js";
import { ISSUER_DID, getIssuerJwksForVerifier } from "../issuer/identity.js";
import { makeErrorResponse } from "@cuncta/shared";
import { requireServiceAuth } from "../auth.js";
import { tokenHashPrefix } from "../oid4vci/accessToken.js";
import { createCNonce, consumePreauthCode, createPreauthCode } from "../oid4vci/preauth.js";
import {
  signOid4vciAccessToken,
  verifyOid4vciAccessTokenEdDSA,
  getOid4vciTokenJwks
} from "../oid4vci/tokenSigning.js";
import { verifyOid4vciProofJwtEdDSA } from "../oid4vci/proofJwt.js";
import {
  getZkStatementsForCredentialConfig,
  listIssuableCredentialConfigs
} from "@cuncta/zk-registry";
import { createOfferChallenge } from "../oid4vci/offerChallenge.js";

const credentialRequestSchema = z.object({
  // Standards-path: configuration id (we treat this repo's `vct` as config id).
  credential_configuration_id: z.string().min(3).optional(),
  // Backward-compat / transitional: allow direct `vct`.
  vct: z.string().min(3).optional(),
  // Transitional: older clients passed subjectDid directly. In standards posture, subject is asserted by proof.
  subjectDid: z.string().min(3).optional(),
  claims: z.record(z.string(), z.unknown()).default({}),
  proof: z
    .object({
      proof_type: z.literal("jwt").optional(),
      jwt: z.string().min(10)
    })
    .optional(),
  statusListId: z.string().min(1).optional(),
  format: z.string().optional()
});

const issueRequestSchema = z.object({
  subjectDid: z.string().min(3),
  vct: z.string().min(3),
  claims: z.record(z.string(), z.unknown()).default({})
});

const tokenRequestSchema = z.object({
  grant_type: z.string().min(3),
  "pre-authorized_code": z.string().optional(),
  tx_code: z.string().optional(),
  scope: z.string().optional(),
  // Non-standard extension: wallet supplies scope_json so issuer can validate against hash-only binding.
  scope_json: z.string().optional()
});

const resolveCredentialConfig = (configId: string) => {
  const raw = String(configId ?? "");
  if (raw.startsWith("sdjwt:")) {
    return { format: "dc+sd-jwt" as const, vct: raw.slice("sdjwt:".length) };
  }
  if (raw.startsWith("di-bbs:")) {
    return { format: "di+bbs" as const, vct: raw.slice("di-bbs:".length) };
  }
  // Backward-compat: config id is the VCT for SD-JWT.
  return { format: "dc+sd-jwt" as const, vct: raw };
};

const hasIssuerOverride = (body: unknown) => {
  if (!body || typeof body !== "object") return false;
  const record = body as Record<string, unknown>;
  return "issuerDid" in record || "issuer" in record || "iss" in record;
};

const parseTokenBody = (body: unknown) => {
  if (typeof body === "string") {
    const params = new URLSearchParams(body);
    return {
      grant_type: params.get("grant_type") ?? "",
      "pre-authorized_code": params.get("pre-authorized_code") ?? undefined,
      tx_code: params.get("tx_code") ?? undefined,
      scope: params.get("scope") ?? undefined,
      scope_json: params.get("scope_json") ?? undefined
    };
  }
  if (body && typeof body === "object") {
    return body as Record<string, unknown>;
  }
  return {};
};

export const buildOid4vciIssuerMetadata = async (input: {
  issuerBaseUrl: string;
  allowExperimentalZk: boolean;
}) => {
  const issuerBaseUrl = input.issuerBaseUrl.replace(/\/$/, "");
  const credentialConfigurationsSupported: Record<string, unknown> = {};

  if (input.allowExperimentalZk) {
    // Registry-driven ZK credential configurations (data > hardcode).
    const issuable = await listIssuableCredentialConfigs().catch(() => []);
    for (const cfg of issuable) {
      if (cfg.format !== "dc+sd-jwt") continue;
      credentialConfigurationsSupported[cfg.credential_configuration_id] = {
        format: "dc+sd-jwt",
        vct: cfg.vct,
        cryptographic_binding_methods_supported: ["did"],
        credential_signing_alg_values_supported: ["EdDSA"],
        proof_types_supported: {
          jwt: { proof_signing_alg_values_supported: ["EdDSA"] }
        }
      };
    }

  }

  return {
    credential_issuer: issuerBaseUrl,
    jwks_uri: `${issuerBaseUrl}/jwks.json`,
    token_endpoint: `${issuerBaseUrl}/token`,
    credential_endpoint: `${issuerBaseUrl}/credential`,
    grant_types_supported: ["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
    token_endpoint_auth_methods_supported: ["none"],
    credential_configurations_supported: credentialConfigurationsSupported
  };
};

export const registerIssuerRoutes = (app: FastifyInstance) => {
  // Internal helper: one-time offer challenges for Aura capability offers (used by gateway).
  app.post(
    "/v1/internal/oid4vci/offer-challenge",
    {
      config: {
        rateLimit: {
          max: config.RATE_LIMIT_IP_TOKEN_PER_MIN,
          timeWindow: "1 minute"
        }
      }
    },
    async (request, reply) => {
      await requireServiceAuth(request, reply, {
        requiredScopes: ["issuer:oid4vci_offer_challenge"]
      });
      if (reply.sent) return;
      const created = await createOfferChallenge();
      return reply.send({
        nonce: created.nonce,
        audience: config.ISSUER_BASE_URL.replace(/\/$/, ""),
        expires_at: created.expiresAt
      });
    }
  );

  // Internal helper for app-gateway to mint a credential offer (pre-authorized code).
  // This is not a public endpoint; gateway is the public surface.
  app.post(
    "/v1/internal/oid4vci/preauth",
    {
      config: {
        rateLimit: {
          max: config.RATE_LIMIT_IP_TOKEN_PER_MIN,
          timeWindow: "1 minute"
        }
      }
    },
    async (request, reply) => {
      await requireServiceAuth(request, reply, { requiredScopes: ["issuer:oid4vci_preauth"] });
      if (reply.sent) return;
      const body = z
        .object({
          vct: z.string().min(3),
          // For now: tx_code support is optional; if provided, it is treated as a one-time PIN.
          tx_code: z.string().min(1).max(32).optional()
        })
        .parse(request.body ?? {});
      const created = await createPreauthCode({
        vct: body.vct,
        ttlSeconds: config.OID4VCI_PREAUTH_CODE_TTL_SECONDS,
        txCode: body.tx_code ?? null,
        scope: null
      });
      return reply.send({
        credential_offer: {
          credential_issuer: config.ISSUER_BASE_URL,
          credential_configuration_ids: [body.vct],
          grants: {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
              "pre-authorized_code": created.preAuthorizedCode,
              ...(body.tx_code ? { tx_code: { length: body.tx_code.length } } : {})
            }
          }
        },
        expires_at: created.expiresAt
      });
    }
  );

  app.get("/v1/issuer", async (_request, reply) => {
    return reply.send({ issuerDid: ISSUER_DID });
  });

  app.get("/jwks.json", async (_request, reply) => {
    const credentialJwks = await getIssuerJwksForVerifier();
    let keys = [...credentialJwks.keys];
    if (
      config.ISSUER_ENABLE_OID4VCI &&
      (config.OID4VCI_TOKEN_SIGNING_JWK || config.OID4VCI_TOKEN_SIGNING_BOOTSTRAP)
    ) {
      const oid4vciJwks = await getOid4vciTokenJwks();
      keys = [...keys, ...oid4vciJwks.keys];
    }
    return reply.send({ keys });
  });

  app.get("/.well-known/openid-credential-issuer", async (_request, reply) => {
    if (!config.ISSUER_ENABLE_OID4VCI) {
      return reply.code(404).send(
        makeErrorResponse("not_found", "Route disabled", {
          devMode: config.DEV_MODE
        })
      );
    }
    const metadata = await buildOid4vciIssuerMetadata({
      issuerBaseUrl: config.ISSUER_BASE_URL,
      allowExperimentalZk: config.ALLOW_EXPERIMENTAL_ZK
    });
    return reply.send(metadata);
  });

  app.post(
    "/token",
    {
      config: {
        rateLimit: {
          max: config.RATE_LIMIT_IP_TOKEN_PER_MIN,
          timeWindow: "1 minute"
        }
      }
    },
    async (request, reply) => {
      if (!config.ISSUER_ENABLE_OID4VCI) {
        return reply.code(404).send(
          makeErrorResponse("not_found", "Route disabled", {
            devMode: config.DEV_MODE
          })
        );
      }
      const body = tokenRequestSchema.parse(parseTokenBody(request.body));
      if (body.grant_type !== "urn:ietf:params:oauth:grant-type:pre-authorized_code") {
        return reply.code(400).send(
          makeErrorResponse("invalid_request", "Unsupported grant type", {
            devMode: config.DEV_MODE
          })
        );
      }
      const hasEdDSAKey =
        Boolean(config.OID4VCI_TOKEN_SIGNING_JWK) || config.OID4VCI_TOKEN_SIGNING_BOOTSTRAP;
      if (!hasEdDSAKey) {
        return reply.code(500).send(
          makeErrorResponse("internal_error", "OID4VCI token signing key not configured", {
            devMode: config.DEV_MODE
          })
        );
      }
      const issuer = config.ISSUER_BASE_URL;
      const audience = config.ISSUER_BASE_URL;
      const scope = (body.scope ?? "credential")
        .split(" ")
        .map((v) => v.trim())
        .filter((v) => v.length > 0);

      const code = body["pre-authorized_code"];
      if (!code) {
        return reply.code(400).send(
          makeErrorResponse("invalid_request", "Missing pre-authorized_code", {
            devMode: config.DEV_MODE
          })
        );
      }
      let vct = "";
      try {
        const consumed = await consumePreauthCode({ code, txCode: body.tx_code ?? null });
        vct = consumed.vct;
      } catch (error) {
        const message = error instanceof Error ? error.message : "preauth_code_invalid";
        return reply.code(400).send(
          makeErrorResponse("invalid_request", "Invalid pre-authorized_code", {
            details: config.DEV_MODE ? message : undefined,
            devMode: config.DEV_MODE
          })
        );
      }

      const accessToken = await signOid4vciAccessToken({
        issuer,
        audience,
        ttlSeconds: config.OID4VCI_ACCESS_TOKEN_TTL_SECONDS,
        scope,
        credentialConfigurationId: vct
      });
      const decoded = (() => {
        try {
          // Not verified here; issuer just minted it.
          const parts = accessToken.split(".");
          const payload = JSON.parse(
            Buffer.from(parts[1] ?? "", "base64url").toString("utf8")
          ) as Record<string, unknown> | null;
          return payload ?? {};
        } catch {
          return {};
        }
      })();
      const jti = String(decoded.jti ?? "");
      const cNonce = await createCNonce({
        tokenJti: jti,
        ttlSeconds: config.OID4VCI_C_NONCE_TTL_SECONDS
      });
      const requestId = (request as { requestId?: string }).requestId;
      log.info("issuer.oid4vci.token.issued", {
        requestId,
        tokenHashPrefix: tokenHashPrefix(accessToken),
        ttlSeconds: config.OID4VCI_ACCESS_TOKEN_TTL_SECONDS,
        credentialConfigurationId: vct
      });
      return reply.send({
        access_token: accessToken,
        token_type: "bearer",
        expires_in: config.OID4VCI_ACCESS_TOKEN_TTL_SECONDS,
        c_nonce: cNonce.cNonce,
        c_nonce_expires_in: config.OID4VCI_C_NONCE_TTL_SECONDS
      });
    }
  );

  app.post(
    "/credential",
    {
      config: {
        rateLimit: {
          max: config.RATE_LIMIT_IP_CREDENTIAL_PER_MIN,
          timeWindow: "1 minute"
        }
      }
    },
    async (request, reply) => {
      if (!config.ISSUER_ENABLE_OID4VCI) {
        return reply.code(404).send(
          makeErrorResponse("not_found", "Route disabled", {
            devMode: config.DEV_MODE
          })
        );
      }
      const requestId = (request as { requestId?: string }).requestId;
      const auth = request.headers.authorization ?? "";
      const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
      let tokenPayload: Record<string, unknown> | null = null;
      try {
        const verified = await verifyOid4vciAccessTokenEdDSA({
          token,
          issuerBaseUrl: config.ISSUER_BASE_URL,
          requiredScopes: ["credential"]
        });
        tokenPayload = verified.payload as Record<string, unknown>;
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        log.warn("issuer.oid4vci.token.invalid", {
          requestId,
          tokenHashPrefix: tokenHashPrefix(token),
          reason: msg
        });
        return reply.code(401).send(
          makeErrorResponse("invalid_request", "Invalid token", {
            devMode: config.DEV_MODE
          })
        );
      }
      if (hasIssuerOverride(request.body)) {
        return reply.code(400).send(
          makeErrorResponse("issuer_not_allowed", "Issuer override not allowed", {
            devMode: config.DEV_MODE
          })
        );
      }

      const body = credentialRequestSchema.parse(request.body);
      if (!body.proof?.jwt) {
        return reply.code(400).send(
          makeErrorResponse("invalid_request", "Missing proof", {
            devMode: config.DEV_MODE
          })
        );
      }
      const configId = body.credential_configuration_id ?? body.vct;
      if (!configId) {
        return reply.code(400).send(
          makeErrorResponse("invalid_request", "Missing credential configuration id", {
            devMode: config.DEV_MODE
          })
        );
      }
      const tokenBoundConfigId = String((tokenPayload ?? {}).vct ?? "").trim();
      if (!tokenBoundConfigId) {
        return reply.code(401).send(
          makeErrorResponse("invalid_request", "Token missing credential binding", {
            devMode: config.DEV_MODE
          })
        );
      }
      if (tokenBoundConfigId !== configId) {
        return reply.code(401).send(
          makeErrorResponse("invalid_request", "Token not valid for requested credential", {
            devMode: config.DEV_MODE
          })
        );
      }
      const tokenJti = String((tokenPayload ?? {}).jti ?? "");
      if (!tokenJti) {
        return reply.code(401).send(
          makeErrorResponse("invalid_request", "Invalid token", {
            devMode: config.DEV_MODE
          })
        );
      }
      const subjectDid = body.subjectDid ?? "";
      if (!subjectDid) {
        return reply.code(400).send(
          makeErrorResponse("invalid_request", "Missing subject DID", {
            devMode: config.DEV_MODE
          })
        );
      }
      // Proof-of-possession: proof.jwt binds the holder key to c_nonce and issuer audience.
      let cNonce = "";
      try {
        const unverified = JSON.parse(
          Buffer.from(body.proof.jwt.split(".")[1] ?? "", "base64url").toString("utf8")
        ) as Record<string, unknown>;
        cNonce = String(unverified.nonce ?? "");
      } catch {
        cNonce = "";
      }
      if (!cNonce || cNonce.length < 8) {
        return reply.code(400).send(
          makeErrorResponse("invalid_request", "Invalid proof nonce", {
            devMode: config.DEV_MODE
          })
        );
      }
      try {
        await verifyOid4vciProofJwtEdDSA({
          proofJwt: body.proof.jwt,
          expectedAudience: config.ISSUER_BASE_URL.replace(/\/$/, ""),
          expectedNonce: cNonce,
          expectedSubjectDid: subjectDid
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : "proof_invalid";
        return reply.code(401).send(
          makeErrorResponse("invalid_request", "Proof invalid", {
            details: config.DEV_MODE ? message : undefined,
            devMode: config.DEV_MODE
          })
        );
      }
      try {
        // One-time semantics for proof nonce (c_nonce).
        const { consumeCNonce } = await import("../oid4vci/preauth.js");
        await consumeCNonce({ cNonce, tokenJti });
      } catch (error) {
        const message = error instanceof Error ? error.message : "c_nonce_invalid_or_consumed";
        return reply.code(401).send(
          makeErrorResponse("invalid_request", "c_nonce invalid", {
            details: config.DEV_MODE ? message : undefined,
            devMode: config.DEV_MODE
          })
        );
      }

      const resolved = resolveCredentialConfig(configId);
      // If the wallet provides a format, ensure it matches the requested configuration id.
      // (OID4VCI allows clients to omit it; in that case we default to the config id’s resolved format.)
      if (body.format && body.format !== resolved.format) {
        return reply.code(400).send(
          makeErrorResponse("invalid_request", "Unsupported format", {
            devMode: config.DEV_MODE
          })
        );
      }
      log.info("issuer.credential.request", {
        requestId,
        credentialConfigurationId: configId,
        vct: resolved.vct,
        format: resolved.format
      });
      try {
        if (resolved.format === "dc+sd-jwt") {
          const c = (body.claims ?? {}) as Record<string, unknown>;

          // Global safety: never accept DOB-like fields, even for non-ZK credentials.
          // (Prevents accidental leakage if a client misconfigures claims.)
          for (const forbidden of ["birthdate_days", "birthdateDays", "dob", "date_of_birth"]) {
            if (forbidden in c) {
              return reply.code(400).send(
                makeErrorResponse("invalid_request", "DOB must not be sent to issuer", {
                  devMode: config.DEV_MODE
                })
              );
            }
          }

          // Registry-driven issuance contract: if this credential config is ZK-backed, validate strictly.
          const zkDefs = await getZkStatementsForCredentialConfig(resolved.vct).catch(() => []);
          const issuable = zkDefs.filter((s) => s.available && s.definition.issuance?.enabled);
          const isZkBacked = issuable.length > 0;
          if (isZkBacked && !config.ALLOW_EXPERIMENTAL_ZK) {
            return reply.code(404).send(
              makeErrorResponse("not_found", "Credential configuration disabled", {
                devMode: config.DEV_MODE
              })
            );
          }
          if (isZkBacked) {
            // Aggregate contract across all statements that share this credential config.
            const allowedClaims = issuable
              .map((s) => new Set(s.definition.issuer_contract.allowed_claims))
              .reduce((acc, set) => new Set(Array.from(acc).filter((k) => set.has(k))));
            const requiredClaims = Array.from(
              new Set(issuable.flatMap((s) => s.definition.issuer_contract.required_claims))
            );
            const allowedSchemesList = issuable
              .map(
                (s) => s.definition.credential_requirements.commitment_scheme_versions_allowed ?? []
              )
              .filter((v) => v.length > 0);
            const allowedSchemes =
              allowedSchemesList.length === 0
                ? null
                : allowedSchemesList.reduce((acc, cur) => acc.filter((v) => cur.includes(v)));

            for (const key of Object.keys(c)) {
              if (!allowedClaims.has(key)) {
                return reply.code(400).send(
                  makeErrorResponse("invalid_request", `Unknown claim: ${key}`, {
                    devMode: config.DEV_MODE
                  })
                );
              }
            }
            for (const key of requiredClaims) {
              if (typeof c[key] === "undefined") {
                return reply.code(400).send(
                  makeErrorResponse("invalid_request", `Missing claim: ${key}`, {
                    devMode: config.DEV_MODE
                  })
                );
              }
            }
            if (allowedSchemes) {
              const scheme =
                typeof c.commitment_scheme_version === "string" ? c.commitment_scheme_version : "";
              if (!scheme) {
                return reply.code(400).send(
                  makeErrorResponse("invalid_request", "Missing commitment_scheme_version", {
                    devMode: config.DEV_MODE
                  })
                );
              }
              if (!allowedSchemes.includes(scheme)) {
                return reply.code(400).send(
                  makeErrorResponse("invalid_request", "Unsupported commitment scheme", {
                    devMode: config.DEV_MODE
                  })
                );
              }
            }
            // Generic structure validation: commitment fields must be decimal bigint strings (issuer never learns DOB).
            for (const key of requiredClaims) {
              if (!key.endsWith("_commitment")) continue;
              const v = typeof c[key] === "string" ? c[key] : "";
              try {
                const asBig = BigInt(v);
                if (asBig <= 0n) throw new Error("non_positive");
              } catch {
                return reply.code(400).send(
                  makeErrorResponse("invalid_request", `Invalid ${key}`, {
                    devMode: config.DEV_MODE
                  })
                );
              }
            }
          }

          const result = await issueCredentialCore({
            subjectDid: subjectDid,
            claims: body.claims,
            vct: resolved.vct,
            format: resolved.format
          });
          return reply.send({ credential: result.credential });
        }
        if (resolved.format === "di+bbs") {
          if (!config.ALLOW_EXPERIMENTAL_ZK) {
            return reply.code(404).send(
              makeErrorResponse("not_found", "Credential configuration disabled", {
                devMode: config.DEV_MODE
              })
            );
          }
          const result = await issueCredentialCore({
            subjectDid: subjectDid,
            claims: body.claims,
            vct: resolved.vct,
            format: resolved.format
          });
          return reply.send({ credential: result.credential });
        }
        return reply.code(400).send(
          makeErrorResponse("invalid_request", "Unsupported credential format", {
            devMode: config.DEV_MODE
          })
        );
      } catch (error) {
        if (error instanceof Error && error.message === "catalog_integrity_failed") {
          return reply.code(503).send(
            makeErrorResponse("catalog_integrity_failed", "Catalog integrity check failed", {
              devMode: config.DEV_MODE
            })
          );
        }
        throw error;
      }
    }
  );

  app.post(
    "/v1/issue",
    {
      config: {
        rateLimit: {
          max: config.RATE_LIMIT_IP_CREDENTIAL_PER_MIN,
          timeWindow: "1 minute"
        }
      }
    },
    async (request, reply) => {
      if (config.NODE_ENV === "production" && !config.DEV_MODE) {
        return reply.code(404).send(
          makeErrorResponse("not_found", "Route disabled", {
            devMode: config.DEV_MODE
          })
        );
      }
      const requestId = (request as { requestId?: string }).requestId;
      if (hasIssuerOverride(request.body)) {
        return reply.code(400).send(
          makeErrorResponse("issuer_not_allowed", "Issuer override not allowed", {
            devMode: config.DEV_MODE
          })
        );
      }
      const body = issueRequestSchema.parse(request.body);
      log.info("issuer.issue.request", { requestId, vct: body.vct });
      let result;
      try {
        result = await issueCredentialCore({
          subjectDid: body.subjectDid,
          claims: body.claims,
          vct: body.vct
        });
      } catch (error) {
        if (error instanceof Error && error.message === "catalog_integrity_failed") {
          return reply.code(503).send(
            makeErrorResponse("catalog_integrity_failed", "Catalog integrity check failed", {
              devMode: config.DEV_MODE
            })
          );
        }
        throw error;
      }
      return reply.send({
        credential: result.credential,
        eventId: result.eventId,
        credentialFingerprint: result.credentialFingerprint
      });
    }
  );

  app.post(
    "/v1/admin/issue",
    {
      config: {
        rateLimit: {
          max: config.RATE_LIMIT_IP_CREDENTIAL_PER_MIN,
          timeWindow: "1 minute"
        }
      }
    },
    async (request, reply) => {
      await requireServiceAuth(request, reply, { requireAdminScope: ["issuer:internal_issue"] });
      if (reply.sent) return;
      const requestId = (request as { requestId?: string }).requestId;
      if (hasIssuerOverride(request.body)) {
        return reply.code(400).send(
          makeErrorResponse("issuer_not_allowed", "Issuer override not allowed", {
            devMode: config.DEV_MODE
          })
        );
      }
      const body = issueRequestSchema.parse(request.body);
      if (!config.ISSUER_INTERNAL_ALLOWED_VCTS.length) {
        return reply.code(403).send(
          makeErrorResponse("invalid_request", "Issuer allowlist not configured", {
            devMode: config.DEV_MODE
          })
        );
      }
      if (!config.ISSUER_INTERNAL_ALLOWED_VCTS.includes(body.vct)) {
        return reply.code(403).send(
          makeErrorResponse("invalid_request", "VCT not allowed", {
            devMode: config.DEV_MODE
          })
        );
      }
      log.info("issuer.internal.issue.request", { requestId, vct: body.vct });
      let result;
      try {
        result = await issueCredentialCore({
          subjectDid: body.subjectDid,
          claims: body.claims,
          vct: body.vct
        });
      } catch (error) {
        if (error instanceof Error && error.message === "catalog_integrity_failed") {
          return reply.code(503).send(
            makeErrorResponse("catalog_integrity_failed", "Catalog integrity check failed", {
              devMode: config.DEV_MODE
            })
          );
        }
        throw error;
      }
      return reply.send({
        credential: result.credential,
        eventId: result.eventId,
        credentialFingerprint: result.credentialFingerprint
      });
    }
  );
};
