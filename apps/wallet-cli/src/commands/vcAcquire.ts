import { z } from "zod";
import { loadWalletState, saveWalletState } from "../walletStore.js";
import { commitDobDaysPoseidonV1Bn254Ds1, randomField } from "@cuncta/zk-commitments-bn254";
import { buildHolderJwtEdDsa, ensureHolderPublicJwk } from "../holder/holderKeys.js";
import { readFile } from "node:fs/promises";

const envSchema = z.object({
  ISSUER_SERVICE_BASE_URL: z.string().url(),
  APP_GATEWAY_BASE_URL: z.string().url().optional()
});

const argsSchema = z.object({
  issuer: z.string().url().optional(),
  configId: z.string().min(3),
  format: z.enum(["dc+sd-jwt", "di+bbs"]).optional(),
  claimsJson: z.string().optional(),
  offer: z.string().optional()
});

const parseArgs = () => {
  const args = process.argv.slice(3);
  const getArg = (name: string) => {
    const index = args.findIndex((arg) => arg === name);
    if (index === -1) return undefined;
    return args[index + 1];
  };
  const issuer = getArg("--issuer");
  const configId = getArg("--config-id") ?? "";
  const format = getArg("--format");
  const claimsJson = getArg("--claims-json");
  const offer = getArg("--offer");
  return argsSchema.parse({ issuer, configId, format, claimsJson, offer });
};

const resolveJsonArg = async (raw: string | undefined, label: "claims_json" | "offer") => {
  if (!raw) return undefined;
  const trimmed = raw.trim();
  if (!trimmed.startsWith("@")) return trimmed;
  const filePath = trimmed.slice(1).trim();
  if (!filePath) {
    throw new Error(`${label}_file_path_missing`);
  }
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

const withHeartbeat = async <T>(stage: string, fn: () => Promise<T>): Promise<T> => {
  const started = Date.now();
  const timer = setInterval(() => {
    console.log(
      `stage=vc.acquire|substage=${stage}|event=heartbeat|elapsedMs=${Date.now() - started}`
    );
  }, 5000);
  timer.unref?.();
  try {
    return await fn();
  } finally {
    clearInterval(timer);
  }
};

export const vcAcquire = async () => {
  const commandStarted = Date.now();
  process.stdout.write("stage=vc.acquire|event=start|elapsedMs=0\n");
  const logStage = (substage: string, event: "start" | "done") => {
    console.log(
      `stage=vc.acquire|substage=${substage}|event=${event}|elapsedMs=${Date.now() - commandStarted}`
    );
  };
  const commandHeartbeat = setInterval(() => {
    console.log(`stage=vc.acquire|event=heartbeat|elapsedMs=${Date.now() - commandStarted}`);
  }, 5000);
  commandHeartbeat.unref?.();
  try {
    logStage("parse", "start");
    const env = envSchema.parse(process.env);
    const args = parseArgs();
    logStage("parse", "done");

    logStage("state.load", "start");
    const state = await loadWalletState();
    const subjectDid = state.did?.did;
    if (!subjectDid) throw new Error("holder_did_missing");
    const holderPublicJwk = await ensureHolderPublicJwk();
    logStage("state.load", "done");

    // Acquire via OID4VCI 1.0 pre-authorized code offer.
    // Default: fetch offer from gateway (public surface) if available.
    const claimsJsonInput = await resolveJsonArg(args.claimsJson, "claims_json");
    const claimsForOffer: Record<string, unknown> =
      claimsJsonInput && claimsJsonInput.trim().length
        ? (() => {
            try {
              return JSON.parse(claimsJsonInput) as Record<string, unknown>;
            } catch (error) {
              const detail = error instanceof Error ? error.message : String(error);
              throw new Error(`claims_json_invalid:${detail}`);
            }
          })()
        : {};
    const offerInput = await resolveJsonArg(args.offer, "offer");

    logStage("offer.resolve", "start");
    const offerObj = await withHeartbeat("offer.resolve", async () => {
      if (offerInput && offerInput.trim().length) {
        return offerInput.trim().startsWith("http://") || offerInput.trim().startsWith("https://")
          ? fetchJson<unknown>(offerInput.trim())
          : Promise.resolve(JSON.parse(offerInput) as unknown);
      }
      if (!env.APP_GATEWAY_BASE_URL) {
        return Promise.resolve(null);
      }
      // Aura capability portability: obtain an offer via challenge+proof to avoid oracle-style issuance.
      if (args.configId.startsWith("aura:")) {
        const domain = typeof claimsForOffer.domain === "string" ? claimsForOffer.domain : "";
        const spaceId =
          typeof claimsForOffer.space_id === "string" ? claimsForOffer.space_id : undefined;
        if (!domain && !spaceId) {
          throw new Error("aura_offer_requires_domain_or_space_id");
        }
        return (async () => {
          const challenge = await fetchJson<{ nonce: string; audience: string }>(
            new URL(
              `/oid4vci/aura/challenge?config_id=${encodeURIComponent(args.configId)}`,
              env.APP_GATEWAY_BASE_URL
            ).toString()
          );
          const now = Math.floor(Date.now() / 1000);
          const proofJwt = await buildHolderJwtEdDsa({
            header: { alg: "EdDSA", typ: "openid4vci-proof+jwt" },
            payload: {
              iss: subjectDid,
              aud: challenge.audience.replace(/\/$/, ""),
              nonce: challenge.nonce,
              iat: now,
              exp: now + 120,
              cnf: { jwk: { kty: "OKP", crv: "Ed25519", x: holderPublicJwk.x, alg: "EdDSA" } }
            }
          });
          return await fetchJson<unknown>(
            new URL("/oid4vci/aura/offer", env.APP_GATEWAY_BASE_URL).toString(),
            {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({
                credential_configuration_id: args.configId,
                subjectDid,
                domain: domain || (spaceId ? `space:${spaceId}` : ""),
                ...(spaceId ? { space_id: spaceId } : {}),
                offer_nonce: challenge.nonce,
                proof_jwt: proofJwt
              })
            }
          );
        })();
      }

      // Standard offer surface (non-aura).
      return fetchJson<unknown>(
        new URL(
          `/oid4vci/offer?vct=${encodeURIComponent(args.configId)}${
            args.format ? `&format=${encodeURIComponent(args.format)}` : ""
          }`,
          env.APP_GATEWAY_BASE_URL
        ).toString()
      );
    });
    logStage("offer.resolve", "done");
    if (!offerObj) {
      throw new Error("oid4vci_offer_missing");
    }
    const offerSchema = z.object({
      credential_offer: z.object({
        credential_issuer: z.string().url(),
        credential_configuration_ids: z.array(z.string().min(3)).min(1),
        grants: z.record(z.string(), z.unknown())
      })
    });
    const parsedOffer = offerSchema.parse(offerObj).credential_offer;
    const preauthGrant = parsedOffer.grants[
      "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    ] as Record<string, unknown> | undefined;
    const preAuthorizedCode =
      typeof preauthGrant?.["pre-authorized_code"] === "string"
        ? (preauthGrant?.["pre-authorized_code"] as string)
        : "";
    if (!preAuthorizedCode) {
      throw new Error("oid4vci_offer_missing_preauth_code");
    }
    const configId = parsedOffer.credential_configuration_ids[0] ?? args.configId;
    const issuerFromOffer = parsedOffer.credential_issuer;
    const resolved = String(configId).startsWith("sdjwt:")
      ? { vct: String(configId).slice("sdjwt:".length), format: "dc+sd-jwt" as const }
      : String(configId).startsWith("di-bbs:")
        ? { vct: String(configId).slice("di-bbs:".length), format: "di+bbs" as const }
        : { vct: String(configId), format: "dc+sd-jwt" as const };

    logStage("issuer.metadata", "start");
    const meta = await withHeartbeat("issuer.metadata", async () =>
      fetchJson<{
        token_endpoint: string;
        credential_endpoint: string;
        issuer_bbs_public_key_b64u?: string;
      }>(new URL("/.well-known/openid-credential-issuer", issuerFromOffer).toString())
    );
    logStage("issuer.metadata", "done");

    const tokenParams = new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      "pre-authorized_code": preAuthorizedCode
    });
    if (String(configId).startsWith("aura:")) {
      const domain = typeof claimsForOffer.domain === "string" ? claimsForOffer.domain : "";
      const spaceId = typeof claimsForOffer.space_id === "string" ? claimsForOffer.space_id : "";
      if (spaceId) {
        tokenParams.set("scope_json", JSON.stringify({ space_id: spaceId }));
      } else if (domain === "marketplace" || domain === "social") {
        tokenParams.set("scope_json", JSON.stringify({ domain }));
      } else {
        throw new Error("aura_token_requires_scope_json_domain_or_space_id");
      }
    }

    logStage("issuer.token", "start");
    const tokenRes = await withHeartbeat("issuer.token", async () =>
      fetchJson<unknown>(meta.token_endpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: tokenParams.toString()
      })
    );
    logStage("issuer.token", "done");
    const tokenSchema = z.object({
      access_token: z.string().min(10),
      c_nonce: z.string().min(10)
    });
    const token = tokenSchema.parse(tokenRes);

    const claims: Record<string, unknown> = { ...claimsForOffer };

    // True ZK age credential (age_credential_v1): wallet sends commitment only, never DOB.
    if (resolved.vct === "age_credential_v1") {
      const birthdateDaysRaw = process.env.WALLET_BIRTHDATE_DAYS ?? "";
      const birthdateDays = Number(birthdateDaysRaw);
      if (!Number.isFinite(birthdateDays)) {
        throw new Error(
          "WALLET_BIRTHDATE_DAYS required for age_credential_v1 issuance (days since epoch)"
        );
      }
      const rand = randomField();
      const commitment = await commitDobDaysPoseidonV1Bn254Ds1({ birthdateDays, rand });
      claims.dob_commitment = commitment.toString();
      claims.commitment_scheme_version = "poseidon_v1_bn254_ds1";
      const stateWithSecrets = state as unknown as {
        zkSecrets?: { age_credential_v1?: Record<string, unknown> };
      };
      stateWithSecrets.zkSecrets = stateWithSecrets.zkSecrets ?? {};
      stateWithSecrets.zkSecrets.age_credential_v1 = {
        birthdate_days: birthdateDays,
        rand: rand.toString(),
        dob_commitment: commitment.toString(),
        commitment_scheme_version: "poseidon_v1_bn254_ds1"
      };
    }

    // Proof-of-possession: bind holder key to c_nonce and issuer audience.
    const now = Math.floor(Date.now() / 1000);
    const proofJwt = await buildHolderJwtEdDsa({
      header: { alg: "EdDSA", typ: "openid4vci-proof+jwt" },
      payload: {
        iss: subjectDid,
        aud: issuerFromOffer.replace(/\/$/, ""),
        nonce: token.c_nonce,
        iat: now,
        exp: now + 120,
        cnf: { jwk: { kty: "OKP", crv: "Ed25519", x: holderPublicJwk.x, alg: "EdDSA" } }
      }
    });

    // Treat configuration id as vct for this repo.
    logStage("issuer.credential", "start");
    const credentialRes = await withHeartbeat("issuer.credential", async () =>
      fetchJson<{ credential: unknown }>(meta.credential_endpoint, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          Authorization: `Bearer ${token.access_token}`
        },
        body: JSON.stringify({
          subjectDid,
          credential_configuration_id: configId,
          // Aura capability credentials are derived server-side from eligibility; client does not supply claims.
          claims: configId.startsWith("aura:") ? {} : claims,
          format: resolved.format,
          proof: { proof_type: "jwt", jwt: proofJwt }
        })
      })
    );
    logStage("issuer.credential", "done");

    type StoredCredential = { vct: string; format: string; configId?: string; credential: unknown };
    const existing = (state as unknown as { credentials?: StoredCredential[] }).credentials ?? [];
    const next = existing.filter((c) => !(c.vct === resolved.vct && c.format === resolved.format));
    next.push({
      vct: resolved.vct,
      format: resolved.format,
      configId,
      credential: credentialRes.credential,
      // For DI+BBS: keep issuer public key alongside the credential so presentation works out-of-the-box.
      ...(resolved.format === "di+bbs" && typeof meta.issuer_bbs_public_key_b64u === "string"
        ? { issuerBbsPublicKeyB64u: meta.issuer_bbs_public_key_b64u }
        : {})
    });
    (state as unknown as { credentials?: StoredCredential[] }).credentials = next;
    await saveWalletState(state);
    console.log(
      JSON.stringify({ ok: true, vct: resolved.vct, format: resolved.format, configId }, null, 2)
    );
  } finally {
    clearInterval(commandHeartbeat);
  }
};
