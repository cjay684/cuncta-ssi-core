import { z } from "zod";
import { createRemoteJWKSet, jwtVerify, decodeJwt } from "jose";
import { presentSdJwtVc } from "@cuncta/sdjwt";
import { sha256Base64Url } from "../crypto/sha256.js";
import { loadWalletState, saveWalletState } from "../walletStore.js";
import { buildHolderJwtEdDsa, ensureHolderPublicJwk } from "../holder/holderKeys.js";

const toOptionalNumber = (value: unknown) => {
  if (value === undefined || value === null || value === "") return undefined;
  const parsed = Number(value);
  return Number.isNaN(parsed) ? undefined : parsed;
};

const envSchema = z
  .object({
    APP_GATEWAY_BASE_URL: z.string().url(),
    KBJWT_TTL_SECONDS: z.preprocess(toOptionalNumber, z.number().optional()),
    WALLET_VERIFY_REQUEST_SIGNATURE: z.preprocess((v) => v !== "false", z.boolean()).default(true),
    BREAK_GLASS_DISABLE_STRICT: z.preprocess((v) => v === "true", z.boolean()).default(false),
    NODE_ENV: z.string().optional(),
    HEDERA_NETWORK: z.enum(["testnet", "previewnet", "mainnet"]).optional()
  })
  .refine(
    (env) =>
      !env.BREAK_GLASS_DISABLE_STRICT ||
      env.NODE_ENV !== "production" ||
      env.HEDERA_NETWORK !== "mainnet",
    {
      message: "BREAK_GLASS_DISABLE_STRICT forbidden on mainnet production",
      path: ["BREAK_GLASS_DISABLE_STRICT"]
    }
  );

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

export const present = async (action = "identity.verify") => {
  const env = envSchema.parse(process.env);
  const state = await loadWalletState();
  // Ensure we can emit cnf.jwk even if signing happens via hardware keystore.
  const holderPublicJwk = await ensureHolderPublicJwk();

  const requestUrl = `${env.APP_GATEWAY_BASE_URL}/oid4vp/request?action=${encodeURIComponent(action)}`;
  const response = await fetch(requestUrl);
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`oid4vp_request_failed: ${text}`);
  }
  const payload = (await response.json()) as {
    action: string;
    nonce: string;
    audience: string;
    expires_at: string;
    requirements: Array<{ vct: string; disclosures: string[] }>;
    request_jwt?: string;
  };

  const strictRequestSignature =
    !env.BREAK_GLASS_DISABLE_STRICT && env.WALLET_VERIFY_REQUEST_SIGNATURE;
  if (payload.request_jwt) {
    const jwksUrl = resolveRequestJwtJwksUrl(payload.request_jwt, {
      strict: strictRequestSignature
    });
    if (jwksUrl) {
      try {
        const JWKS = createRemoteJWKSet(new URL(jwksUrl));
        await jwtVerify(payload.request_jwt, JWKS, {
          algorithms: ["EdDSA"],
          typ: "oid4vp-request+jwt"
        });
      } catch (err) {
        throw new Error(
          `request_signature_verification_failed:${err instanceof Error ? err.message : "unknown"}`
        );
      }
    }
  } else if (strictRequestSignature) {
    throw new Error("request_jwt_missing_strict_mode");
  }

  const requirement = payload.requirements[0];
  if (!requirement) {
    throw new Error("requirements_missing");
  }
  const credential = state.credentials?.find((cred) => cred.vct === requirement.vct);
  if (!credential) {
    throw new Error("credential_missing");
  }

  // WalletState can carry SD-JWT credentials (compact string) or DI+BBS credentials (JSON object).
  // The OID4VP flow here is SD-JWT-based; if the stored credential isn't a compact SD-JWT string,
  // fall back to legacy `sdJwt` field if present, else fail with a clear error.
  const sdJwtCandidate =
    typeof credential.credential === "string"
      ? credential.credential
      : typeof (credential as unknown as { sdJwt?: unknown }).sdJwt === "string"
        ? ((credential as unknown as { sdJwt?: string }).sdJwt ?? "")
        : "";
  if (!sdJwtCandidate || typeof sdJwtCandidate !== "string") {
    throw new Error("credential_not_sd_jwt_string");
  }

  const sdJwtPresentation = await presentSdJwtVc({
    sdJwt: sdJwtCandidate,
    disclose: requirement.disclosures
  });

  const nowSeconds = Math.floor(Date.now() / 1000);
  const secondsUntilExpiry = Math.max(
    0,
    Math.floor((Date.parse(payload.expires_at) - Date.now()) / 1000)
  );
  const baseTtl = Number.isFinite(env.KBJWT_TTL_SECONDS as number)
    ? Math.max(30, Math.min(600, Number(env.KBJWT_TTL_SECONDS)))
    : 120;
  const ttlSeconds = Math.max(1, Math.min(baseTtl, secondsUntilExpiry));
  const kbJwt = await buildHolderJwtEdDsa({
    header: { alg: "EdDSA", typ: "kb+jwt" },
    payload: {
      aud: payload.audience,
      nonce: payload.nonce,
      iat: nowSeconds,
      exp: nowSeconds + ttlSeconds,
      sd_hash: sha256Base64Url(sdJwtPresentation),
      cnf: { jwk: { kty: "OKP", crv: "Ed25519", x: holderPublicJwk.x, alg: "EdDSA" } }
    }
  });

  const presentation = `${sdJwtPresentation}${kbJwt}`;
  state.lastPresentation = {
    action,
    presentation,
    nonce: payload.nonce,
    audience: payload.audience
  };
  await saveWalletState(state);
  console.log(JSON.stringify(state.lastPresentation, null, 2));
};

export const __test__ = { resolveRequestJwtJwksUrl };
