# Cuncta SSI Core — Master Codebase Overview

> Generated exclusively from source code. No documentation was consulted.

---

## Table of Contents

1. [Repository Structure](#1-repository-structure)
2. [Identity — DID Lifecycle](#2-identity--did-lifecycle)
3. [Credential Issuance — SD-JWT & DI+BBS](#3-credential-issuance--sd-jwt--dibbs)
4. [OID4VCI — Standards-Based Issuance Protocol](#4-oid4vci--standards-based-issuance-protocol)
5. [Verification Pipeline — OID4VP](#5-verification-pipeline--oid4vp)
6. [Zero-Knowledge Proofs — Groth16 on BN254](#6-zero-knowledge-proofs--groth16-on-bn254)
7. [Aura — Behavioral Reputation to Capability Credentials](#7-aura--behavioral-reputation-to-capability-credentials)
8. [Policy Engine & Compliance Profiles](#8-policy-engine--compliance-profiles)
9. [Hedera Anchoring — Outbox, Worker, Reconciler](#9-hedera-anchoring--outbox-worker-reconciler)
10. [Privacy — Pseudonymization, Pepper, GDPR/DSR](#10-privacy--pseudonymization-pepper-gdprdsr)
11. [Data Retention & Cleanup](#11-data-retention--cleanup)
12. [Social Layer — Credential-Gated Communities](#12-social-layer--credential-gated-communities)
13. [Command Center — Intent-Based Action Planner](#13-command-center--intent-based-action-planner)
14. [Service-to-Service Authentication](#14-service-to-service-authentication)
15. [Production Hardening & Surface Enforcement](#15-production-hardening--surface-enforcement)
16. [Trust Registry](#16-trust-registry)
17. [Database Schema](#17-database-schema)
18. [Wallet CLI & Mobile Wallet](#18-wallet-cli--mobile-wallet)

---

## 1. Repository Structure

A pnpm monorepo (`pnpm-workspace.yaml`) with two workspace roots:

- **`apps/`** — 11 deployable services and tools
- **`packages/`** — 17 shared libraries

### Apps

| App                 | Purpose                                                    |
| ------------------- | ---------------------------------------------------------- |
| `app-gateway`       | Public API gateway; only public-facing service             |
| `did-service`       | Hedera DID lifecycle (create, update, deactivate, resolve) |
| `issuer-service`    | Credential issuance, Aura, OID4VCI, privacy, anchoring     |
| `verifier-service`  | Presentation verification, OID4VP, ZK proofs               |
| `policy-service`    | Policy evaluation and compliance profiles                  |
| `social-service`    | Credential-gated social features                           |
| `wallet-cli`        | CLI wallet for DID/credential operations                   |
| `mobile-wallet`     | Mobile wallet (test harness)                               |
| `web-demo`          | React demo UI                                              |
| `integration-tests` | End-to-end integration tests                               |
| `contract-e2e`      | Contract/guard tests                                       |

### Packages

| Package                  | Purpose                                                          |
| ------------------------ | ---------------------------------------------------------------- |
| `shared`                 | Service auth, pseudonymization, canonical JSON, surface registry |
| `db`                     | Knex PostgreSQL client, migrations                               |
| `sdjwt`                  | SD-JWT VC issuance, presentation, verification                   |
| `di-bbs`                 | DI+BBS (BLS12-381) credential format                             |
| `hedera`                 | Hedera client, topic management, anchor publishing, fee budgets  |
| `wallet`                 | Wallet state, key generation                                     |
| `wallet-keystore`        | Platform-specific key storage (DPAPI, file)                      |
| `payments`               | Fee schedules, payment request building                          |
| `trust-registry`         | Signed issuer trust bundles                                      |
| `policy-profiles`        | Compliance profile definitions (default/uk/eu)                   |
| `verifier-helper`        | SD-JWT presentation verification utilities                       |
| `zk-age-snark`           | Groth16 age proof circuit and prover                             |
| `zk-commitments-bn254`   | Poseidon commitments on BN254                                    |
| `zk-proof-groth16-bn254` | Groth16 proof/verify wrapper (snarkjs)                           |
| `zk-registry`            | ZK statement definitions (registry-driven)                       |

### Credential Formats vs. ZK Layer

Two distinct layers exist in the codebase and should not be conflated:

- **Credential formats** (selective disclosure): `sdjwt` and `di-bbs` — these determine _how claims are encoded and selectively revealed_ during presentation.
- **Predicate ZK layer**: `zk-age-snark`, `zk-commitments-bn254`, `zk-proof-groth16-bn254` — Groth16 SNARKs on BN254 that prove _statements about claims_ (e.g., "age ≥ 18") without revealing the claim value. This is orthogonal to the credential format.

Compliance profiles (`policy-profiles`) and the trust registry (`trust-registry`) span both layers. UK and EU compliance overlays can tighten verification requirements at the policy level, affecting both format-level checks (revocation, binding) and ZK predicate enforcement.

---

## 2. Identity — DID Lifecycle

DIDs are created via a **two-phase request/submit pattern**. The server never holds the user's private key.

### Phase 1 — Request (server prepares the transaction)

```204:261:apps/did-service/src/routes/dids.ts
  app.post("/v1/dids/create/request", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["did:create_request"] });
    if (reply.sent) return;
    const requestId = (request as { requestId?: string }).requestId;
    const body = createRequestSchema.parse(request.body);
    // ...
      const response = await registrar.generateCreateDIDRequest(
        registrarOptions,
        buildRegistrarProviders(config.HEDERA_NETWORK) as RegistrarProviders
      );
      const payloadToSign = extractPayloadToSign(response);
      // ...
      const { entry, state } = stateStore.create({
        publicKeyMultibase: body.publicKeyMultibase,
        network: body.network,
        payloadToSign,
        operationState: created.operationState,
        options: normalizeOptions(body.options)
      });
      // ...
      return reply.send({
        state,
        signingRequest: {
          publicKeyMultibase: created.publicKeyMultibase,
          alg: "EdDSA",
          payloadToSignB64u: bytesToBase64Url(payloadToSign),
          createdAt: entry.createdAt ?? created.createdAt
        }
      });
```

The server generates a `payloadToSign` via the Hiero DID SDK and stores ephemeral state (UUID-keyed, TTL-bounded). The client signs offline.

### Phase 2 — Submit (user provides signature)

```275:347:apps/did-service/src/routes/dids.ts
  app.post("/v1/dids/create/submit", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["did:create_submit"] });
    // ...
    const stateEntry = stateStore.consume(body.state);
    // ...
    const signatureBytes = base64UrlToBytes(body.signatureB64u);
    // ...
      const response = await registrar.submitCreateDIDRequest(
        {
          state: stateEntry.operationState as Registrar.SubmitCreateDIDRequestOptions["state"],
          signature: signatureBytes,
          visibilityTimeoutMs: config.DID_VISIBILITY_TIMEOUT_MS,
          waitForDIDVisibility: waitForVisibility
        },
        buildRegistrarProviders(config.HEDERA_NETWORK) as RegistrarProviders
      );
```

The ephemeral state is **consumed** (one-time use). The DID is anchored to Hedera Consensus Service.

### Full DID Lifecycle

The same two-phase pattern applies to **update** and **deactivate**:

```349:414:apps/did-service/src/routes/dids.ts
  app.post("/v1/dids/update/request", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["did:update_request"] });
    // ...
  });
```

```484:528:apps/did-service/src/routes/dids.ts
  app.post("/v1/dids/deactivate/request", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["did:deactivate_request"] });
    // ...
  });
```

DID resolution is the only unauthenticated endpoint on the did-service itself. Externally, the gateway's surface enforcement registry controls what is exposed publicly — resolution is proxied through it, while all mutating DID routes are classified as `internal` and require service JWT auth at the gateway level:

```583:613:apps/did-service/src/routes/dids.ts
  app.get("/v1/dids/resolve/:did", async (request, reply) => {
    // ...
    const response = await resolver.resolveDID(params.did);
    // ...
    return reply.send({ didDocument });
  });
```

### Production Hardening

The DID service enforces strict posture at startup:

```46:78:apps/did-service/src/server.ts
  if (config.NODE_ENV === "production" && config.PUBLIC_SERVICE) {
    log.error("public.service.not_allowed", { env: config.NODE_ENV });
    throw new Error("public_service_not_allowed");
  }
  if (config.NODE_ENV === "production" && !config.TRUST_PROXY) {
    log.error("trust.proxy.required", { env: config.NODE_ENV });
    throw new Error("trust_proxy_required_in_production");
  }
  if (config.NODE_ENV === "production" && !isPrivateAddress(config.SERVICE_BIND_ADDRESS)) {
    // ...
    throw new Error("public_bind_not_allowed");
  }
  if (config.ALLOW_INSECURE_DEV_AUTH) {
    if (config.NODE_ENV === "production") {
      // ...
      throw new Error("insecure_dev_auth_not_allowed");
    }
    const localDevAllowed =
      config.NODE_ENV === "development" && isLoopbackAddress(config.SERVICE_BIND_ADDRESS);
    if (!localDevAllowed) {
      // ...
      throw new Error("insecure_dev_auth_not_allowed");
    }
```

---

## 3. Credential Issuance — SD-JWT & DI+BBS

### SD-JWT (Primary Format)

The `@cuncta/sdjwt` package implements Selective Disclosure JWT. Claims marked for selective disclosure are replaced with SHA-256 digests:

```76:111:packages/sdjwt/src/index.ts
export async function issueSdJwtVc(options: IssueSdJwtVcOptions): Promise<string> {
  const alg = options.issuerJwk.alg ?? "EdDSA";
  const protectedHeader = {
    alg,
    typ: options.typMode === "legacy" ? "vc+sd-jwt" : "dc+sd-jwt",
    kid: options.issuerJwk.kid
  };
  const payload: SdJwtPayload = { ...options.payload };
  const disclosures: string[] = [];
  const digests: string[] = [];
  for (const path of options.selectiveDisclosure) {
    const value = getByPath(payload, path);
    // ...
    const salt = randomBytes(16).toString("base64url");
    const disclosure = encodeDisclosure([salt, claimName, value]);
    const digest = sha256Base64Url(disclosure);
    disclosures.push(disclosure);
    digests.push(digest);
    deleteByPath(payload, path);
  }
  if (digests.length > 0) {
    payload._sd = digests;
    payload._sd_alg = "sha-256";
  }
  const key = await importJWK(options.issuerJwk, alg);
  const jwt = await new SignJWT(payload).setProtectedHeader(protectedHeader).sign(key);
  const segments = [jwt, ...disclosures];
  return `${segments.join("~")}~`;
}
```

Each disclosure is `base64url([salt, claimName, value])`. The credential is `jwt~disclosure1~disclosure2~...~`.

### Issuance Flow (issuer-service)

```185:316:apps/issuer-service/src/issuer/issuance.ts
export const issueCredential = async (input: {
  subjectDid: string;
  claims: Record<string, unknown>;
  vct: string;
}) => {
  const catalog = await getCatalogEntry(input.vct);
  // ...
  validateClaims(catalog.json_schema, input.claims);
  const hashes = getDidHashes(input.subjectDid);
  const privacyStatus = await getPrivacyStatus(hashes);
  if (privacyStatus.tombstoned) {
    throw new Error("privacy_erased");
  }
  // ...
  return await db.transaction(async (trx) => {
    // ... status list management ...
    const sdJwt = await issueSdJwtVc({
      issuerJwk: issuerJwk as never,
      payload: {
        iss: issuerDid,
        sub: input.subjectDid,
        iat: Math.floor(Date.now() / 1000),
        vct: input.vct,
        status: credentialStatus,
        ...input.claims
      },
      selectiveDisclosure: catalog.sd_defaults,
      typMode: "strict"
    });
    // ... issuance event recording ...
    // ... anchor outbox enqueue ...
    // ... audit log ...
  });
};
```

Every issuance:

1. Validates claims against the credential catalog's JSON Schema (Ajv)
2. Checks for privacy tombstones (GDPR erasure)
3. Allocates a status list index (for revocation)
4. Issues the SD-JWT with catalog-defined selective disclosure paths
5. Records an `issuance_events` row (subject DID stored as pseudonymized hash only)
6. Enqueues an `ISSUED` anchor to Hedera
7. Writes an audit log entry

### Status List Revocation (W3C BitstringStatusList)

```319:397:apps/issuer-service/src/issuer/issuance.ts
export const revokeCredential = async (input: { ... }) => {
  // ...
  return await db.transaction(async (trx) => {
    // ...
    const bitBytes = decodeBitstring(version.bitstring_base64);
    setBit(bitBytes, record.status_index, true);
    const encodedList = encodeBitstring(bitBytes);
    // ... version increment ...
    // ... anchor REVOKED event ...
  });
};
```

Revocation flips a bit in a base64url-encoded bitstring and publishes a new version.

---

## 4. OID4VCI — Standards-Based Issuance Protocol

### Pre-Authorized Code Flow

Pre-auth codes are **hash-only** — the raw code is returned to the client but only the SHA-256 hash is stored:

```16:42:apps/issuer-service/src/oid4vci/preauth.ts
export const createPreauthCode = async (input: CreatePreauthCodeInput) => {
  const db = await getDb();
  const code = randomBytes(32).toString("base64url");
  const codeHash = sha256Hex(code);
  const txCodeHash = input.txCode ? sha256Hex(input.txCode) : null;
  // IMPORTANT: persist hash-only (GDPR minimization). Raw scope is client-supplied at redemption time.
  const scopeHash = input.scope ? hashCanonicalJson(input.scope) : null;
  const expiresAt = new Date(Date.now() + input.ttlSeconds * 1000).toISOString();
  // ...
  await db("oid4vci_preauth_codes").insert({
    ...baseRow,
    scope_hash: scopeHash
  });
  // ...
  return { preAuthorizedCode: code, expiresAt };
};
```

Consumption enforces **one-time semantics**:

```44:78:apps/issuer-service/src/oid4vci/preauth.ts
export const consumePreauthCode = async (input: { code: string; txCode?: string | null }) => {
  // ...
  const codeHash = sha256Hex(input.code);
  const row = await db("oid4vci_preauth_codes").where({ code_hash: codeHash }).first();
  if (!row) throw new Error("preauth_code_invalid");
  if (row.consumed_at) throw new Error("preauth_code_consumed");
  if (row.expires_at && new Date(row.expires_at as string) <= new Date())
    throw new Error("preauth_code_expired");
  // ... tx_code validation ...
  // One-time semantics: consume on successful token redemption.
  const updated = await db("oid4vci_preauth_codes")
    .where({ code_hash: codeHash })
    .whereNull("consumed_at")
    .andWhere("expires_at", ">", now)
    .update({ consumed_at: now });
  if (!updated) throw new Error("preauth_code_consumed");
  // ...
};
```

### c_nonce (Client Nonce) — Same Pattern

```82:111:apps/issuer-service/src/oid4vci/preauth.ts
export const createCNonce = async (input: { tokenJti: string; ttlSeconds: number }) => {
  const db = await getDb();
  const cNonce = randomBytes(32).toString("base64url");
  const nonceHash = sha256Hex(cNonce);
  const tokenJtiHash = sha256Hex(input.tokenJti);
  // ...
};

export const consumeCNonce = async (input: { cNonce: string; tokenJti: string }) => {
  // ...
  const updated = await db("oid4vci_c_nonces")
    .where({ nonce_hash: nonceHash, token_jti_hash: tokenJtiHash })
    .whereNull("consumed_at")
    .andWhere("expires_at", ">", now)
    .update({ consumed_at: now });
  if (!updated) throw new Error("c_nonce_invalid_or_consumed");
};
```

### Token Exchange (/token)

```412:582:apps/issuer-service/src/routes/issuer.ts
  app.post("/token", { ... }, async (request, reply) => {
    // ...
    // Consume the one-time pre-authorized code
    const consumed = await consumePreauthCode({ code, txCode: body.tx_code ?? null });
    vct = consumed.vct;
    preauthScopeHash = consumed.scopeHash ?? null;
    // ...
    // Hash-only scope binding for Aura capability credentials
    if (preauthScopeHash) {
      const scope = parseAuraScopeJson(scopeJson);
      const computed = hashCanonicalJson(canonicalScope);
      if (computed !== preauthScopeHash) {
        return reply.code(400).send(makeErrorResponse("invalid_request", "scope_json mismatch", ...));
      }
      // ...
    }
    // Sign access token + create c_nonce
    const accessToken = await signOid4vciAccessToken({ ... });
    const cNonce = await createCNonce({ tokenJti: jti, ttlSeconds: ... });
    return reply.send({
      access_token: accessToken,
      token_type: "bearer",
      expires_in: ...,
      c_nonce: cNonce.cNonce,
      c_nonce_expires_in: ...
    });
  });
```

### Credential Endpoint (/credential)

```584:951:apps/issuer-service/src/routes/issuer.ts
  app.post("/credential", { ... }, async (request, reply) => {
    // Verify access token
    const verified = await verifyOid4vciAccessTokenEdDSA({ ... });
    // Token-to-credential binding enforcement
    if (tokenBoundConfigId !== configId) {
      return reply.code(401).send(makeErrorResponse("invalid_request", "Token not valid for requested credential", ...));
    }
    // Proof-of-possession: proof.jwt binds the holder key to c_nonce and issuer audience
    await verifyOid4vciProofJwtEdDSA({ ... });
    // One-time semantics for proof nonce
    await consumeCNonce({ cNonce, tokenJti });
    // ...
    // For Aura capability credentials: claims are SERVER-DERIVED, not client-supplied
    if (configId.startsWith("aura:")) {
      const eligibility = await checkCapabilityEligibility({ ... });
      const claims = buildClaimsFromRule(eligibility.ruleLogic, context);
      const result = await issueCredentialCore({ subjectDid, claims, vct: resolved.vct });
      return reply.send({ credential: result.credential });
    }
    // DOB rejection — never accept date-of-birth fields
    for (const forbidden of ["birthdate_days", "birthdateDays", "dob", "date_of_birth"]) {
      if (forbidden in c) {
        return reply.code(400).send(makeErrorResponse("invalid_request", "DOB must not be sent to issuer", ...));
      }
    }
    // ZK-backed credential contract validation (registry-driven)
    // ... commitment field validation (BigInt strings) ...
    const result = await issueCredentialCore({ subjectDid, claims: body.claims, vct: resolved.vct });
    return reply.send({ credential: result.credential });
  });
```

Key security properties:

- Pre-auth codes, c_nonces, and offer challenges are all **hash-only + TTL + one-time**
- Token is bound to a specific `credential_configuration_id`
- Issuer override attempts (`issuerDid`, `issuer`, `iss` in body) are explicitly rejected
- DOB fields are **forbidden** — the issuer never sees date of birth
- ZK commitment fields must be valid decimal BigInt strings

---

## 5. Verification Pipeline — OID4VP

The core verification function (`verifyPresentationCore`) runs a strict sequential pipeline:

```404:1031:apps/verifier-service/src/core/verifyPresentation.ts
export const verifyPresentationCore = async (
  input: VerifyPresentationCoreInput
): Promise<VerifyPresentationCoreResult> => {
```

### Step 1: Challenge Validation

```546:571:apps/verifier-service/src/core/verifyPresentation.ts
    if (decision === "ALLOW" && hasRequirements) {
      if (!challengeRow) {
        deny("challenge_not_found");
      } else if (challengeRow.audience && challengeRow.audience !== input.audience) {
        deny("aud_mismatch");
      } else if (challengeRow.consumed_at) {
        deny("challenge_consumed");
      } else if (challengeRow.expires_at && new Date(challengeRow.expires_at) <= new Date()) {
        deny("challenge_expired");
      } else {
        challengeValid = true;
      }
    }

    // Challenge is consumed once it passes challenge validation (decision === "ALLOW" here),
    // before the rest of presentation verification runs. That means:
    // - If challenge validation DENYs (aud mismatch, expiry, already consumed), it is NOT consumed.
    // - If later steps DENY (bad signature, failed predicates, revoked, etc.), the challenge is already consumed.
    // Replay protection is strict via an atomic whereNull("consumed_at") update (prevents concurrent reuse).
    if (decision === "ALLOW" && challengeValid) {
      const consumed = await db("verification_challenges")
        .where({ challenge_hash: challengeHash, action_id: input.actionId })
        .whereNull("consumed_at")
        .andWhere("expires_at", ">", new Date().toISOString())
        .update({ consumed_at: new Date().toISOString() });
```

### Step 2: KB-JWT Holder Binding

```630:683:apps/verifier-service/src/core/verifyPresentation.ts
    if (decision === "ALLOW") {
      if (!kbJwt) {
        deny("kb_jwt_missing");
      } else {
        // ... decode KB-JWT header, validate EdDSA alg ...
        const cnf = kbDecoded.cnf as { jwk?: Record<string, unknown> } | undefined;
        if (!cnf?.jwk) {
          deny("kb_jwt_missing_cnf");
        } else {
          // Import holder key from cnf.jwk
          const holderKey = await importJWK(holderJwk as never, "EdDSA");
          const kbPayload = await jwtVerify(kbJwt, holderKey).catch(() => null);
          if (!kbPayload) deny("binding_invalid");
          // Verify aud, nonce, sd_hash, exp
          if (!audValid) deny("aud_mismatch");
          if (kbNonce !== input.nonce) deny("nonce_mismatch");
          if (sdHash !== expectedBindingHash) deny("sd_hash_mismatch");
```

### Step 3: SD-JWT Signature Verification

```776:787:apps/verifier-service/src/core/verifyPresentation.ts
      const result = await verifySdJwtVc({
        token: sdJwtPresentation,
        jwks: jwksForVerify,
        allowLegacyTyp: false
      });
      payload = result.payload;
      claims = result.claims;
```

### Step 4: Privacy Tombstone Check

```795:802:apps/verifier-service/src/core/verifyPresentation.ts
          const tombstone = await db("privacy_tombstones")
            .whereIn("did_hash", [subjectHash, subjectHashLegacy].filter(Boolean))
            .first();
          if (tombstone) {
            deny("privacy_erased");
            allowObligations = false;
          }
```

### Step 5: DID Key Binding

```814:837:apps/verifier-service/src/core/verifyPresentation.ts
      if (config.ENFORCE_DID_KEY_BINDING && activeBinding.mode === "kb-jwt" && activeBinding.require) {
        if (!holderCnfJwk) {
          deny("kb_jwt_missing_cnf");
        } else {
          const didDocument = await resolveDidDocument(payload.sub as string);
          const authorized = isCnfKeyAuthorizedByDidDocument(didDocument, holderCnfJwk);
          if (!authorized.ok) {
            deny(authorized.reason);
          }
```

The DID key binding function extracts authorized Ed25519 keys from the DID document and matches against the CNF key:

```121:139:apps/verifier-service/src/didKeyBinding.ts
export const isCnfKeyAuthorizedByDidDocument = (
  didDocument: unknown,
  cnfJwkRaw: unknown
): { ok: true } | { ok: false; reason: "cnf_invalid" | "did_key_not_authorized" } => {
  const cnfJwk = normalizeEd25519Jwk(cnfJwkRaw);
  if (!cnfJwk) return { ok: false, reason: "cnf_invalid" };
  const cnfBytes = decodeBase64Url(cnfJwk.x);
  const candidates = extractAuthorizedEd25519Keys(didDocument);
  for (const candidate of candidates) {
    if (candidate.jwk && candidate.jwk.x === cnfJwk.x) return { ok: true };
    if (candidate.publicKeyBytes && bytesEqual(candidate.publicKeyBytes, cnfBytes)) return { ok: true };
  }
  return { ok: false, reason: "did_key_not_authorized" };
};
```

### Step 6: Issuer Trust

```867:880:apps/verifier-service/src/core/verifyPresentation.ts
      if (decision === "ALLOW" && requirement?.issuer) {
        const issuerCheck = await checkIssuerRule({ issuerDid, rule: requirement.issuer as never });
        if (!issuerCheck.ok) deny(issuerCheck.reason);
      }
```

Three modes — `allowlist`, `env`, `trust_registry`:

```8:39:apps/verifier-service/src/core/issuerTrust.ts
export const checkIssuerRule = async (input: {
  issuerDid: string;
  rule: IssuerRule;
}): Promise<...> => {
  if (rule.mode === "allowlist") {
    const allowed = rule.allowed ?? [];
    if (allowed.includes("*") || allowed.includes(input.issuerDid)) return { ok: true };
    return { ok: false, reason: "issuer_not_allowed" };
  }
  if (rule.mode === "env") {
    const envDid = rule.env ? process.env[rule.env] : undefined;
    if (envDid && envDid === input.issuerDid) return { ok: true };
    return { ok: false, reason: "issuer_not_allowed" };
  }
  // trust_registry mode
  const trusted = await isTrustedIssuer({ issuerDid: input.issuerDid, requireMark: mark });
  if (!trusted.trusted) return { ok: false, reason: "issuer_not_trusted" };
  return { ok: true };
};
```

### Step 7: Predicate Evaluation

```920:925:apps/verifier-service/src/core/verifyPresentation.ts
      if (decision === "ALLOW" && requirement) {
        const predicatesOk = requirement.predicates.every((predicate) => evaluatePredicate(predicate, claims));
        if (!predicatesOk) deny("predicate_failed");
      }
```

Supported operators: `eq`, `neq`, `gte`, `lte`, `in`, `exists`. Supports ISO timestamp comparison for freshness checks.

### Step 8: ZK Predicate Proofs

```893:918:apps/verifier-service/src/core/verifyPresentation.ts
        if (requiresZk) {
          // ...
          const zk = await verifyRequiredZkPredicates({
            requiredPredicates: zkPredicates,
            zkProofs: input.zkProofs,
            requestHash: input.requestHash,
            nonce: input.nonce,
            audience: input.audience,
            requestJwt: input.requestJwt,
            claims,
            expectedVct: requirement.vct
          }).catch(() => ({ ok: false, reasons: ["zk_proof_invalid"] }));
```

### Step 9: Revocation Check

```964:973:apps/verifier-service/src/core/verifyPresentation.ts
      if (decision === "ALLOW" && requirement?.revocation?.required !== false) {
        // ...
        const statusCheck = await verifyStatusListEntry(status as Record<string, unknown>);
        if (!statusCheck.valid) deny(statusCheck.reason ?? "revoked");
      }
```

### Step 10: Policy Version Floor

```438:447:apps/verifier-service/src/core/verifyPresentation.ts
      if (floorVersion > 0 && pinnedPolicyVersion < floorVersion) {
        return {
          decision: "DENY",
          reasons: ["policy_version_downgrade"],
          // ...
        };
      }
```

### Fail-Closed Behavior

Dependency failures produce a standard DENY (non-oracular — doesn't reveal why):

```76:81:apps/verifier-service/src/core/verifyPresentation.ts
export const dependencyFailureDeny = () => ({
  decision: "DENY" as const,
  reasons: ["not_allowed"],
  obligationExecutionId: null as null,
  obligationsExecuted: [] as unknown[]
});
```

---

## 6. Zero-Knowledge Proofs — Groth16 on BN254

### Registry-Driven Architecture

ZK statements are defined in JSON files in `packages/zk-registry/statements/`. Each statement defines:

- Circuit references (WASM, proving key, verifying key) with SHA-256 hashes
- Public input schema and ordering
- Required bindings (nonce, audience, request_hash)
- Issuer, verifier, and wallet contracts

### Verification

```26:259:apps/verifier-service/src/zk/verifyZkPredicates.ts
export const verifyRequiredZkPredicates = async (input: { ... }) => {
  // ...
  for (const req of input.requiredPredicates) {
    const statement = await getZkStatement(statementId);
    // ...
    // Enforce request binding (nonce, audience, request_hash)
    for (const binding of statement.definition.required_bindings) {
      const expected = sha256ToField(input[binding]).toString();
      if (pub[pubKey] !== expected) deny("..._mismatch");
    }
    // Param constraints: policy params must match public inputs
    for (const c of statement.definition.verifier_contract.param_constraints) {
      if (pubValue !== String(policyValue)) deny("zk_param_mismatch");
    }
    // Context constraints: zk_context from signed request must match
    for (const c of statement.definition.verifier_contract.context_constraints) {
      if (pubValue !== String(ctxValue)) deny("zk_context_mismatch");
    }
    // Day drift bounds
    if (Math.abs(currentDay - serverDay) > maxDayDrift) deny("zk_day_drift");
    // Commitment linkage: disclosed commitment must match proof public input
    for (const field of statement.definition.credential_requirements.required_commitment_fields) {
      if (typeof pub[field] !== "undefined" && pub[field] !== String(disclosed)) deny("zk_commitment_mismatch");
    }
    // Cryptographic verification
    const ok = await verifyGroth16({ verificationKey: vkJson, proof: proof.proof, publicSignals: proof.public_signals });
    if (!ok.ok) deny("zk_proof_invalid");
  }
};
```

### Mainnet Hardening

```81:87:apps/verifier-service/src/zk/verifyZkPredicates.ts
    if (config.HEDERA_NETWORK === "mainnet" && config.ALLOW_EXPERIMENTAL_ZK) {
      const prov = statement.definition.setup_provenance ?? "unknown";
      if (prov !== "ceremony_attested") {
        deny("zk_setup_not_allowed_on_mainnet");
      }
    }
```

On mainnet, only ceremony-attested trusted setups are accepted.

---

## 7. Aura — Behavioral Reputation to Capability Credentials

### Signal Processing

The Aura worker polls `aura_signals` and aggregates by subject+domain:

```112:360:apps/issuer-service/src/aura/auraWorker.ts
export const processAuraSignalsOnce = async () => {
  const db = await getDb();
  // ... integrity check on all enabled rules ...
  const pendingSignals = await db("aura_signals").whereNull("processed_at").orderBy("created_at", "asc").limit(200);
  // ...
  // Group by subject_did_hash::domain
  for (const [key, signals] of grouped.entries()) {
    // Privacy check
    const privacy = await getPrivacyStatus({ primary: subjectDidHash });
    if (privacy.tombstoned || privacy.restricted) {
      // Mark processed, skip
      continue;
    }
    // Find applicable rules
    const applicable = rules.filter((rule) => ruleAppliesToDomain(String(rule.domain ?? ""), domain));
    for (const rule of applicable) {
      // Compute score with anti-collusion
      const { score, diversity } = computeScore(windowSignals, ruleLogic);
      // Compute tier
      const tierComputed = computeTierFromScore(score, ruleLogic);
      const clampedLevel = clampTierByDiversity({ tierLevel: tierComputed.tierLevel, ... });
      // Enqueue issuance if eligible
      if (diversity >= diversityMin && clampedLevel >= minTierLevel) {
        await db("aura_issuance_queue").insert({ ... }).onConflict(["rule_id", "subject_did_hash", "reason_hash"]).ignore();
      }
    }
    // Upsert aura_state
    await db("aura_state").insert({ subject_did_hash: subjectDidHash, domain, state: { score, diversity, tier, ... } })
      .onConflict(["subject_did_hash", "domain"]).merge({ ... });
  }
};
```

### Score Computation with Anti-Collusion

```35:74:apps/issuer-service/src/aura/auraWorker.ts
const computeScore = (signals, ruleLogic) => {
  const counterpartyMap = new Map<string, { count: number; weightSum: number }>();
  for (const signal of signals) {
    // Group by counterparty
  }
  const cap = parseNumber(ruleLogic.per_counterparty_cap, 0);
  const decay = parseNumber(ruleLogic.per_counterparty_decay_exponent, 0.5);
  const weights = Array.from(counterpartyMap.values()).map((entry) => {
    const effectiveCount = cap > 0 ? Math.min(entry.count, cap) : entry.count;
    const averageWeight = entry.weightSum / entry.count;
    const effectiveWeightSum = averageWeight * effectiveCount;
    return effectiveWeightSum / Math.pow(effectiveCount, decay);
  });
  const total = weights.reduce((sum, value) => sum + value, 0);
  // Collusion detection: top-2 concentration
  const sorted = [...weights].sort((a, b) => b - a);
  const topTwo = sorted.slice(0, 2).reduce((sum, value) => sum + value, 0);
  const concentration = total > 0 ? topTwo / total : 0;
  const antiCollusionMultiplier = concentration > threshold ? multiplier : 1;
  const diversity = Array.from(counterpartyMap.keys()).filter((key) => key !== "none").length;
  return { score: total * antiCollusionMultiplier, diversity };
};
```

Anti-gaming mechanics:

- **Per-counterparty cap**: Max signals counted from any single counterparty
- **Decay exponent**: Diminishing returns from repeated counterparty interactions
- **Collusion detection**: If top-2 counterparties exceed concentration threshold, a multiplier penalty applies
- **Diversity minimum**: Higher tiers require minimum unique counterparties

### Tier System

```8:83:apps/issuer-service/src/aura/tier.ts
export const deriveTierDefs = (ruleLogic: Record<string, unknown>): TierDef[] => {
  // Support custom tiers via score.tiers array, or fallback to bronze/silver/gold
  const minSilver = parseNumber(score.min_silver, 5);
  const minGold = parseNumber(score.min_gold, 12);
  return [
    { name: "bronze", min_score: Number.NEGATIVE_INFINITY },
    { name: "silver", min_score: minSilver },
    { name: "gold", min_score: minGold }
  ].sort((a, b) => a.min_score - b.min_score);
};

export const clampTierByDiversity = (input: { ... }) => {
  // Diversity clamping: e.g. { min_for_silver: 2, min_for_gold: 5 }
  for (const [key, value] of Object.entries(diversityRule)) {
    if (!key.startsWith("min_for_")) continue;
    // ...
    if (input.diversity < min) {
      maxAllowed = Math.min(maxAllowed, level - 1);
    }
  }
  return Math.max(0, Math.min(maxAllowed, input.tiers.length - 1));
};
```

### Rule Contract Validation

```32:47:apps/issuer-service/src/aura/ruleContract.ts
export const isDomainPatternValid = (value: string) => {
  const trimmed = value.trim();
  if (!trimmed) return { ok: false as const, reason: "domain_missing" };
  if (trimmed === "*") return { ok: false as const, reason: "domain_wildcard_forbidden" };
  if (trimmed.endsWith("*")) {
    const prefix = trimmed.slice(0, -1);
    if (!prefix.endsWith(":")) return { ok: false as const, reason: "domain_pattern_invalid" };
    if (prefix.length < 3) return { ok: false as const, reason: "domain_pattern_too_broad" };
  }
  return { ok: true as const };
};
```

Guards: bare `*` is forbidden. Prefix patterns must be namespaced (e.g., `space:*`), with minimum 3-char prefix.

### Rule Integrity (Signed + Anchored)

```147:205:apps/issuer-service/src/aura/auraIntegrity.ts
export const verifyAuraRuleIntegrity = async (row: AuraRuleRow) => {
  // Validate: output_vct present, domain pattern valid, purpose text present
  if (row.enabled) {
    const outputVct = String(row.output_vct ?? "").trim();
    if (!outputVct) throw new Error("aura_integrity_failed");
    const domainValid = isDomainPatternValid(domainRaw);
    if (!domainValid.ok) throw new Error("aura_integrity_failed");
    const purpose = getRulePurpose(ruleLogic);
    if (!purpose) throw new Error("aura_integrity_failed");
  }
  // Verify JWS signature on canonical rule hash
  const ruleHash = computeAuraRuleHash(row);
  if (!row.rule_signature) throw new Error("aura_integrity_failed");
  await verifyAuraRuleSignature(ruleHash, row.rule_signature);
};
```

Every rule is signed with EdDSA (JWS). Changes are anchored to Hedera as `AURA_RULE_CHANGE` events. The worker **halts** if integrity verification fails:

```374:377:apps/issuer-service/src/aura/auraWorker.ts
      if (workerStatus.lastError === "aura_integrity_failed") {
        auraWorkerHalted = true;
        log.error("aura.worker.halted", { reason: "aura_integrity_failed" });
      }
```

### Privacy-Safe Batch Anchoring

```134:198:apps/issuer-service/src/aura/auraWorker.ts
  // Privacy-safe anchoring: per-run batch receipts with no subject hashes.
  if (config.ANCHOR_AUTH_SECRET) {
    // ...
    for (const [domain, list] of byDomain.entries()) {
      const hashes = list.map((s) => String(s.event_hash ?? "")).filter(Boolean).sort();
      // Deterministic batch hash: binds the event set and the active rule versions
      const batchHash = hashCanonicalJson({ event_hashes: hashes, rules: applicableRules });
      const payloadHash = hashCanonicalJson({
        event: "AURA_BATCH",
        domain,
        window_start: windowStart,
        window_end: windowEnd,
        signal_count: list.length,
        batch_hash: batchHash
      });
      await db("anchor_outbox").insert({
        // ... no subject_did_hash in payload_meta ...
      });
    }
  }
```

Batch anchors contain **domain, window, signal count, and a hash of event hashes** — never subject identifiers.

---

## 8. Policy Engine & Compliance Profiles

The policy service evaluates action requirements. The verifier fetches requirements and applies compliance overlays:

```213:236:apps/verifier-service/src/core/verifyPresentation.ts
const applyComplianceOverlayToPolicyLogic = (profile, logic) => {
  // Overlays can ONLY tighten rules, never loosen
  if (overlay.binding?.require) {
    next.binding = { ...(next.binding ?? { mode: "kb-jwt", require: true }), require: true };
  }
  if (overlay.requirements?.revocationRequired) {
    for (const req of next.requirements) {
      req.revocation = { ...(req.revocation ?? { required: true }), required: true };
    }
  }
  return next;
};
```

Profiles: `default`, `uk`, `eu`. Flags: `enforceOriginAudience`, `failClosedDependencies`, `statusListStrict`.

---

## 9. Hedera Anchoring — Outbox, Worker, Reconciler

### Outbox Pattern

Events are enqueued to `anchor_outbox` with status `PENDING`:

```89:117:apps/issuer-service/src/issuer/issuance.ts
const enqueueAnchor = async (trx, input) => {
  const payloadMeta = {
    ...input.payloadMeta,
    ...signAnchorMeta(config.ANCHOR_AUTH_SECRET, {
      payloadHash: input.payloadHash,
      eventType: input.eventType
    })
  };
  await trx("anchor_outbox").insert({
    outbox_id: randomUUID(),
    event_type: input.eventType,
    payload_hash: input.payloadHash,
    payload_meta: payloadMeta,
    status: "PENDING",
    // ...
  }).onConflict("payload_hash").ignore();
};
```

### Worker

```81:312:apps/issuer-service/src/hedera/anchorWorker.ts
export const processAnchorOutboxOnce = async (publisher?) => {
  // Reclaim stale PROCESSING rows
  await db("anchor_outbox").where({ status: "PROCESSING" })
    .andWhere("processing_started_at", "<", staleBefore)
    .update({ status: "PENDING", ... });
  // Fetch pending rows
  const rows = await db("anchor_outbox")
    .whereIn("status", ["PENDING", "FAILED"])
    .andWhere("next_retry_at", "<=", now)
    .orderBy("created_at", "asc")
    .limit(config.OUTBOX_BATCH_SIZE);
  // For each row:
  //   1. Claim as PROCESSING
  //   2. Check for existing receipt (idempotency)
  //   3. Publish to Hedera HCS topic
  //   4. Store receipt
  //   5. Mark CONFIRMED
  // On failure: exponential backoff, max attempts → DEAD
};
```

### Event Types Anchored

| Event Type                                | What It Anchors                                                                              |
| ----------------------------------------- | -------------------------------------------------------------------------------------------- |
| `ISSUED`                                  | Credential issuance (hash of eventId, vct, statusListId, statusIndex, credentialFingerprint) |
| `REVOKED`                                 | Credential revocation (hash of eventId, statusListId, statusIndex, revokedAt)                |
| `AURA_BATCH`                              | Processed signal batch (domain, window, signal count, batch hash — no subject IDs)           |
| `AURA_DERIVED`                            | Aura capability issuance                                                                     |
| `AURA_RESET`                              | Aura state reset                                                                             |
| `AURA_RULE_CHANGE`                        | Rule modification (rule_id, domain, output_vct, version)                                     |
| `AUDIT_LOG_HEAD`                          | Periodic audit log integrity hash                                                            |
| `ISSUER_KEY_ROTATE` / `ISSUER_KEY_REVOKE` | Key lifecycle events                                                                         |

All anchored payloads contain **only hashes and metadata** — never raw DIDs, credentials, or claims.

### Anchor Reconciler

After writing to Hedera, the system doesn't just trust the API response — it reconciles DB receipts against the Hedera mirror node to verify the ledger write actually landed. The reconciler fetches the topic message by sequence number, recomputes the SHA-256 hash of the mirror message bytes, and compares it to the stored `payload_hash`. It also verifies anchor auth metadata (HMAC signature + timestamp) if present:

```118:207:apps/issuer-service/src/hedera/anchorReconciler.ts
      // Fetch from mirror node
      const mirrorRes = await fetchTopicMessageBySequence(
        config.MIRROR_NODE_BASE_URL, topicId, sequenceNumber, ...);
      // ...
      mirrorMessageHash = sha256Hex(mirrorRes.messageBytes);
      // ...
      if (mirrorSha !== payloadHash) {
        status = "MISMATCH"; reason = "payload_hash_mismatch";
      }
      // ...verify anchor_auth_sig and anchor_auth_ts via verifyAnchorMeta...
```

Reconciliation runs on a periodic timer (`ANCHOR_RECONCILER_POLL_MS`), avoids overlapping runs, throttles mirror API calls (200ms between requests), and records results in `anchor_reconciliations` with statuses: `VERIFIED`, `NOT_FOUND`, `MISMATCH`, `INVALID_AUTH`, `ERROR`.

---

## 10. Privacy — Pseudonymization, Pepper, GDPR/DSR

### Pseudonymizer

DIDs are never stored in cleartext. Two mechanisms:

```7:14:packages/shared/src/pseudonymizer.ts
export const createSha256Pseudonymizer = (): Pseudonymizer => ({
  didToHash: (did: string) => createHash("sha256").update(did).digest("hex")
});

export const createHmacSha256Pseudonymizer = (input: { pepper: string }): Pseudonymizer => ({
  didToHash: (did: string) =>
    createHmac("sha256", input.pepper).update(did).digest("hex").toLowerCase()
});
```

- **HMAC-SHA256 with pepper** — primary (production)
- **SHA-256** — legacy (dev only, forbidden in production)

### Pepper Management

```24:39:apps/issuer-service/src/pseudonymizer.ts
const getPepper = () => {
  if (config.PSEUDONYMIZER_PEPPER) {
    return config.PSEUDONYMIZER_PEPPER;
  }
  if (config.NODE_ENV === "production") {
    throw new Error("pseudonymizer_pepper_missing");
  }
  if (!generatedPepper) {
    generatedPepper = randomBytes(32).toString("base64url");
  }
  // ...
  return generatedPepper;
};
```

Production **requires** `PSEUDONYMIZER_PEPPER`. In dev, a random ephemeral pepper is generated.

### Pepper Fingerprint Consistency Check

```82:126:apps/issuer-service/src/pseudonymizer.ts
export const ensurePseudonymizerConsistency = async () => {
  const db = await getDb();
  const fingerprint = getPepperFingerprint();
  const existing = await db("system_metadata").where({ key: FINGERPRINT_KEY }).first();
  if (!existing) {
    // First run: store fingerprint
    await db("system_metadata").insert({ key: FINGERPRINT_KEY, value: fingerprint, ... });
  } else if (existing.value !== fingerprint) {
    if (config.NODE_ENV === "production") {
      throw new Error("pseudonymizer_mismatch");
    }
    // Dev: warn but continue
  }
  // Detect presence of legacy (non-peppered) rows
};
```

If the pepper changes in production, the service **crashes** (`pseudonymizer_mismatch`). This prevents silent data corruption.

### Dual-Hash Lookup

```60:67:apps/issuer-service/src/pseudonymizer.ts
export const getDidHashes = (did: string) => {
  const primary = getPrimaryPseudonymizer().didToHash(did);
  const legacy = getLegacyHash(did);
  return { primary, legacy };
};

export const getLookupHashes = (hashes: { primary: string; legacy?: string | null }) =>
  hashes.legacy ? [hashes.primary, hashes.legacy] : [hashes.primary];
```

Lookups check both primary (HMAC) and legacy (SHA256) hashes for backward compatibility during migration.

### DSR (Data Subject Request) Flow

**Step 1: Request** — user provides DID, gets nonce + audience:

```323:354:apps/issuer-service/src/routes/privacy.ts
  app.post("/v1/privacy/request", async (request, reply) => {
    // ...
    const { primary, legacy } = getDidHashes(body.did);
    const nonce = randomBytes(32).toString("base64url");
    await db("privacy_requests").insert({
      request_id: requestId,
      did_hash: didHash,
      nonce_hash: sha256Hex(nonce),
      audience,
      expires_at: expiresAt,
      // ...
    });
    return reply.send({ requestId, nonce, audience, expires_at: expiresAt });
  });
```

**Step 2: Confirm** — user proves DID ownership via KB-JWT:

```356:419:apps/issuer-service/src/routes/privacy.ts
  app.post("/v1/privacy/confirm", async (request, reply) => {
    // ... validate nonce hash, expiry ...
    await verifyKbJwt({ kbJwt: body.kbJwt, nonce: body.nonce, audience: row.audience });
    // ... consume request, issue DSR token ...
    return reply.send({ dsrToken, expires_at: expiresAt });
  });
```

**Step 3: Erase** — atomic deletion across all tables:

```591:658:apps/issuer-service/src/routes/privacy.ts
  app.post("/v1/privacy/erase", async (request, reply) => {
    // ...
    await db.transaction(async (trx) => {
      await trx("aura_state").whereIn("subject_did_hash", lookup).del();
      await trx("aura_signals").whereIn("subject_did_hash", lookup).del();
      await trx("aura_issuance_queue").whereIn("subject_did_hash", lookup).del();
      await trx("obligation_events").whereIn("subject_did_hash", lookup).del();
      await trx("obligations_executions").whereIn("subject_did_hash", lookup).del();
      await trx("rate_limit_events").whereIn("subject_hash", lookup).del();
      await trx("command_center_audit_events").whereIn("subject_hash", lookup).del();
      await trx("privacy_requests").whereIn("did_hash", lookup).del();
      await trx("privacy_tokens").whereIn("did_hash", lookup).del();
      await trx("privacy_restrictions").whereIn("did_hash", lookup).del();
      await trx("zk_age_group_members").whereIn("subject_did_hash", lookup).del();
      // Unlink issuance events (keep event, remove subject linkage)
      await trx("issuance_events").whereIn("subject_did_hash", lookup)
        .update({ subject_did_hash: null });
      // Create tombstone
      for (const hash of lookup) {
        await trx("privacy_tombstones").insert({ did_hash: hash, erased_at: erasedAt })
          .onConflict("did_hash").merge({ erased_at: erasedAt });
      }
    });
    // ...
    return reply.send({
      status: "erased",
      note: "On-chain anchors are immutable; off-chain linkability removed.",
      // ...
    });
  });
```

Key properties:

- Issuance events are **unlinked** (subject_did_hash set to null) — event stays for audit but subject is gone
- Tombstone prevents re-creation of data for the erased subject
- Hedera anchors are **immutable** but contain only hashes, so they can't be linked back
- DSR tokens are rotated after each operation
- Erase completion tracking scans `information_schema.columns` for any residual `*did_hash*` / `*subject_hash*` columns

### Export

```421:556:apps/issuer-service/src/routes/privacy.ts
  app.get("/v1/privacy/export", async (request, reply) => {
    // ... DSR token auth ...
    // Returns: issuance events, aura state, telemetry counts, anchor outbox/receipts
    const payload = {
      subject: { did_hash: didHash },
      generated_at: new Date().toISOString(),
      issuance,
      aura: auraState,
      telemetry: { obligation_events, rate_limit_events, aura_signals },
      anchors: { outbox: outboxRows, receipts, status_lists }
    };
  });
```

---

## 11. Data Retention & Cleanup

The cleanup worker enforces TTL-based retention:

```46:148:apps/issuer-service/src/cleanup/cleanupWorker.ts
export const runCleanupOnce = async () => {
  // Verification challenges: consumed/expired past cutoff
  const challengesDeleted = await db("verification_challenges").where(...).del();
  // Rate limit events
  const rateLimitsDeleted = await db("rate_limit_events").where("created_at", "<", cutoffRateLimits).del();
  // Obligation events
  const obligationsDeleted = await db("obligation_events").where("created_at", "<", cutoffObligations).del();
  // Aura signals
  const auraSignalsDeleted = await db("aura_signals").where("created_at", "<", cutoffAura).del();
  // Aura state (re-derivable from recent signals)
  const auraStateDeleted = await db("aura_state").where("updated_at", "<", cutoffAuraState).del();
  // Aura issuance queue (terminal rows only)
  const auraQueueDeleted = await db("aura_issuance_queue")
    .whereIn("status", ["ISSUED", "FAILED"]).andWhere("updated_at", "<", cutoffAuraQueue).del();
  // Audit logs
  const auditDeleted = await db("audit_logs").where("created_at", "<", cutoffAudit).del();
  // OID4VCI codes, nonces, offer challenges (expired/consumed)
  // ...
  // Enqueue audit head anchor
  await enqueueAuditHeadAnchor();
};
```

Configurable retention windows:

- `RETENTION_VERIFICATION_CHALLENGES_DAYS` (default 7)
- `RETENTION_RATE_LIMIT_EVENTS_DAYS` (default 7)
- `RETENTION_OBLIGATION_EVENTS_DAYS` (default 30)
- `RETENTION_AURA_SIGNALS_DAYS` (default 30)
- `RETENTION_AURA_STATE_DAYS` (default 180)
- `RETENTION_AURA_ISSUANCE_QUEUE_DAYS` (default 30)
- `RETENTION_AUDIT_LOGS_DAYS` (default 90)

---

## 12. Social Layer — Credential-Gated Communities

### Capability Gating

Every write action passes through `verifyAndGate()` which:

1. Checks privacy status (tombstoned/restricted)
2. Fetches policy requirements
3. Validates the user's credential presentation
4. Logs the action (attempt/allow/deny/complete)

Capabilities: `cuncta.social.space.member`, `cuncta.social.space.poster`, `cuncta.social.space.moderator`, `cuncta.social.space.steward`.

### Spaces

Trust-bounded communities with policy packs defining join/post/moderate/govern requirements. Policy packs can be **pinned by hash** to prevent mid-session changes.

### Crews

Micro-groups within spaces. Join via `social.crew.join` capability OR captain/moderator invite. Not invite-only.

### Challenges

Time-bound activities (daily/weekly/ad_hoc) with streak tracking. Completion requires evidence (post/reply). Streaks tracked via `current_count` and `best_count`.

### Banter

Threaded real-time chat with four thread types: `space_chat`, `challenge_chat`, `hangout_chat`, `crew_chat`. Rate limits scale by Aura tier (bronze: 6/window, silver: 12, gold: 20). Messages auto-expire after 10 days.

### Sync Sessions

Three modes:

- **Scroll Sync**: Synchronized scrolling with WebSocket event streaming
- **Listen Sync**: Synchronized audio with broadcast control and reactions
- **Hangouts**: Lightweight voice/presence rooms (control plane only)

All require permission tokens. Tier-gated event rate limits.

### Presence

Three modes: `quiet`, `active`, `immersive`. TTL-based expiry (default 600s). Max 10 pings per 20-second window. Opt-out via `show_on_presence` setting.

### Leaderboards

Scoring formula: `sqrt(posts) + sqrt(replies) + 1.8 * sqrt(challenge_completions) * diversity_weight`

Square roots prevent spam dominance. Diversity weight rewards consistent multi-day activity.

### Pulse

Contextual activity cards: `crew_active`, `hangout_live`, `challenge_ending`, `streak_risk`, `rank_up`. User-configurable per space.

### Media

S3-compatible presigned upload flow. Auto-generates 320x320 JPEG thumbnails via Sharp. SHA-256 + size + MIME verification. Owner-based access control. Stale upload cleanup.

---

## 13. Command Center — Intent-Based Action Planner

`POST /v1/command/plan` accepts natural-language intents and maps them to actions:

- `"join hangout"` → `sync.hangout.join_session`
- `"send banter"` → `banter.message.send`
- `"complete challenge"` → `challenge.complete`
- `"open space"` → `social.space.create`

Returns: `action_plan`, `required_capabilities`, `ready_state` (READY / MISSING_PROOF / DENIED / NEEDS_REFINEMENT), `next_best_actions`, `feeQuote`.

Audit events stored pseudonymized in `command_center_audit_events`. Subject to DSR erasure and retention cleanup.

---

## 14. Service-to-Service Authentication

Each service has its own JWT secret with scope-based authorization:

```6:93:apps/did-service/src/auth.ts
export const requireServiceAuth = async (request, reply, options?) => {
  const serviceSecret =
    config.SERVICE_JWT_SECRET_DID ??
    (config.ALLOW_LEGACY_SERVICE_JWT_SECRET ? config.SERVICE_JWT_SECRET : undefined);
  const nextSecret = config.SERVICE_JWT_SECRET_NEXT;
  // ... fail-closed if no secret configured ...
  const token = extractBearerToken(request.headers.authorization);
  // ...
  try {
    let payload;
    try {
      payload = await verifyServiceJwt(token, {
        audience,
        secret: serviceSecret,
        issuer: "app-gateway",
        subject: "app-gateway",
        requiredScopes: options?.requiredScopes
      });
    } catch (error) {
      // Scope errors are not retried; signature errors try next secret
      if (nextSecret) {
        payload = await verifyServiceJwt(token, { ..., secret: nextSecret, ... });
      } else { throw error; }
    }
  } catch (error) {
    if (error.message === "jwt_missing_required_scope") {
      await reply.code(403).send(makeErrorResponse("service_auth_scope_missing", ...));
    }
    await reply.code(401).send(makeErrorResponse("invalid_request", "Invalid service token", ...));
  }
};
```

Secret rotation supported via `SERVICE_JWT_SECRET_NEXT`. Scope examples: `did:create_request`, `issuer:oid4vci_preauth`, `verifier:presentations_verify`, `social:proxy`.

---

## 15. Production Hardening & Surface Enforcement

### Strict DB Role

```57:70:apps/issuer-service/src/dbRole.ts
export const enforceStrictDbRole = async () => {
  if (!config.STRICT_DB_ROLE) return;
  const forbiddenWriteTables = ["policies", "policy_version_floor"];
  for (const tableName of forbiddenWriteTables) {
    await probeReadAccess(tableName);
    if (await hasWritePrivilege(tableName)) {
      throw new Error(`strict_db_role_violation:${tableName}`);
    }
  }
};
```

Probes actual PostgreSQL privileges with `DELETE ... WHERE FALSE` inside a rolled-back transaction.

### Signed Surface Registry

The surface registry is a cryptographically signed definition of every allowed route, its visibility (`public`, `internal`, `admin`, `dev_test_only`), and its auth requirements. The signing pipeline is an EdDSA JWS with canonicalization version pinning:

```354:356:scripts/security/sign-surface-registry.mjs
  const jwsCompact = await new CompactSign(Buffer.from(canonicalRegistryText, "utf8"))
    .setProtectedHeader({ alg: "EdDSA", typ: "surface-registry+json", kid, canon: CANON_VERSION })
    .sign(key);
```

At startup, the gateway (and issuer-service) loads the bundle and verifies the signature against `SURFACE_REGISTRY_PUBLIC_KEY`. On main-branch CI, the public key is **required** — missing it fails the build:

```97:103:scripts/security/sign-surface-registry.mjs
const shouldRequireSignatureInCi = () => {
  if (process.env.CI !== "true") return false;
  const ref = process.env.GITHUB_REF ?? "";
  const refName = process.env.GITHUB_REF_NAME ?? "";
  return ref === "refs/heads/main" || refName === "main";
};
```

**Fail-closed enforcement** is the critical property. In production with `PUBLIC_SERVICE=true`, the gateway's preHandler hook checks every incoming request against the compiled surface routes. If a route exists in code but is absent from the registry, it is blocked with a 404:

```85:96:apps/app-gateway/src/surfaceEnforcement.ts
  app.addHook("preHandler", async (request: FastifyRequest, reply: FastifyReply) => {
    if (!enabled) return;
    const routePath = request.routeOptions?.url ?? request.url.split("?")[0];
    const matched = matchSurfaceRoute(compiled, { method: request.method, path: routePath });
    if (!matched) {
      return reply
        .code(404)
        .send(makeErrorResponse("not_found", "not found", { devMode: input.config.DEV_MODE }));
    }
    // ...
  });
```

`dev_test_only` routes return 404 or 410 in production. `internal`/`admin` routes require service JWT auth with scope enforcement. If the registry has zero compiled routes for the service, startup itself throws.

### Backup Restore Mode

```113:123:apps/did-service/src/server.ts
  app.addHook("preHandler", async (request, reply) => {
    if (!config.BACKUP_RESTORE_MODE) return;
    const path = request.url.split("?")[0];
    if (path.startsWith("/v1/dids/create")) {
      return reply.code(503).send(
        makeErrorResponse("maintenance_mode", "Service in backup restore mode", ...)
      );
    }
  });
```

---

## 16. Trust Registry

Signed JSON bundle containing trusted issuers with trust marks. Verification enforces JWS signature and checks for PII leakage. Used by the verifier service during issuer trust evaluation.

```8:39:apps/verifier-service/src/core/issuerTrust.ts
export const checkIssuerRule = async (input) => {
  // mode: allowlist → check against allowed list
  // mode: env → check against environment variable
  // mode: trust_registry → check against signed registry bundle
  const trusted = await isTrustedIssuer({ issuerDid, requireMark: mark });
  if (!trusted.trusted) return { ok: false, reason: "issuer_not_trusted" };
  return { ok: true };
};
```

---

## 17. Database Schema

PostgreSQL managed by Knex migrations in `packages/db`. Key tables:

**Identity & Credentials:**

- `credential_types` — VCT definitions, JSON schemas, SD-JWT defaults
- `issuance_events` — Credential issuance records (subject as pseudonymized hash)
- `status_lists` + `status_list_versions` — Revocation bitstrings
- `issuer_keys` — Issuer signing keys with rotation

**Policy:**

- `actions` — Action definitions
- `policies` — Policy logic (versioned, signed)
- `policy_version_floor` — Minimum policy versions

**Verification:**

- `verification_challenges` — OID4VP challenge requests (nonce, audience, policy pinning)

**OID4VCI:**

- `oid4vci_preauth_codes` — Hash-only pre-authorized codes
- `oid4vci_c_nonces` — Hash-only client nonces
- `oid4vci_offer_challenges` — Offer challenge nonces
- `oid4vp_request_hashes` — Request hash tracking

**Aura:**

- `aura_rules` — Rule definitions (signed, versioned)
- `aura_signals` — Behavioral signals
- `aura_state` — Aggregated state per subject+domain
- `aura_issuance_queue` — Pending capability issuances

**Anchoring:**

- `anchor_outbox` — Hedera anchor message queue
- `anchor_receipts` — Receipts (topic_id, sequence_number, consensus_timestamp)

**Privacy:**

- `privacy_requests` — DSR requests
- `privacy_tokens` — DSR session tokens
- `privacy_restrictions` — Restricted subjects
- `privacy_tombstones` — Erasure markers

**Social:**

- `social_profiles`, `social_posts`, `social_replies`, `social_follows`
- `social_spaces`, `social_space_memberships`, `social_space_posts`
- `social_space_crews`, `social_space_crew_members`
- `social_space_challenges`, `social_space_challenge_participation`, `social_space_streaks`
- `social_space_banter_threads`, `social_banter_messages`, `social_banter_reactions`
- `sync_sessions`, `sync_session_participants`, `sync_session_events`
- `social_space_presence_pings`, `presence_space_states`
- `social_media_assets`
- `social_space_pulse_preferences`
- `social_action_log`

**Audit:**

- `audit_logs` — All major operations
- `command_center_audit_events` — Command planner events
- `system_metadata` — Key-value config (pepper fingerprint, rule hashes)

---

## 18. Wallet CLI & Mobile Wallet

### Wallet CLI Commands

| Command                | Action                                   |
| ---------------------- | ---------------------------------------- |
| `did:create`           | Create DID (default onboarding)          |
| `did:create:user-pays` | Self-funded DID creation                 |
| `did:rotate`           | Rotate DID root key                      |
| `did:recovery:setup`   | Install recovery key                     |
| `did:recovery:rotate`  | Rotate using recovery key                |
| `did:deactivate`       | Deactivate DID                           |
| `vc:acquire`           | Acquire credential via OID4VCI           |
| `present`              | Build presentation for action            |
| `vp:respond`           | Respond to OID4VP request                |
| `verify`               | Verify last presentation                 |
| `aura:simulate`        | Loop present+verify to emit aura signals |
| `aura:claim`           | Claim derived aura credential            |
| `privacy:flow`         | Run DSR request+confirm demo             |

### Wallet Keystore

Platform-specific key storage. File-based keystore is **blocked in production**:

- `createWindowsDpapiKeyStore()` — Windows DPAPI-encrypted
- `createNodeFileKeyStore()` — File-based (dev only)

Keys are stored encrypted at rest (DPAPI on Windows); the `WalletKeyStore` interface exposes only `sign(purpose, payload)` and never returns exportable private key material (`MUST NOT return exportable private key material` — `packages/wallet-keystore/src/types.ts`). File-based keystore is blocked in production.

### Mobile Wallet Tests

Sprint tests validate:

- Software key restrictions and mainnet guards
- Vault encryption at rest
- KB-JWT binding (claims, signature, SD hash)
- Disclosure selection and filtering
- Relying party tracking (first seen, policy hash changes)
- Privacy: logging omits raw audience values

---

# Appendix: Compatibility & Trust Contracts (Code-Anchored)

This appendix captures interoperability targets and trust-model assumptions implied by the codebase, plus a short list of **explicit decisions the platform should commit to** to avoid “accidental hybrids” (internally coherent but incompatible with third-party wallets/verifiers).

Note: `CODEBASE_OVERVIEW.md` is derived from source code. This appendix intentionally avoids citing external specs or publication dates; it describes what the implementation does and where it needs a deliberate compatibility stance.

## A) Interoperability Targets (As Implemented)

### Protocol rails

- **OID4VCI-style issuance** exists end-to-end (wallet obtains access token + c_nonce; issuer serves metadata + token + credential).
- **OID4VP-style presentation** exists (verifier serves a request object; wallet responds with presentation; verifier verifies and returns allow/deny).

### Credential formats

- **Primary VC format:** SD-JWT VC (`dc+sd-jwt`) with selective disclosure and KB-JWT holder binding.
- **Optional format:** DI+BBS (`di+bbs`) is present as an alternate credential format path.

### DID method (Hedera)

- DID lifecycle operations use a dedicated did-service and a resolver, but the repo does not currently contain a single explicit “did:hedera v1 vs v2 controller model” compatibility statement.
- This matters for key rotation and recovery semantics: whether “control authority” is treated as identifier-key-derived vs controller-property-derived.

## B) Status / Revocation Contract (Where Interop Can Drift)

### Current behavior (issuer)

- Issued SD-JWT payloads embed a `status` object whose shape matches a **W3C Bitstring Status List entry** (fields like `type: "BitstringStatusListEntry"`, `statusListIndex`, `statusListCredential`).
- The issuer serves a `BitstringStatusListCredential` JSON object at `/status-lists/:id`, and includes a JWT proof (`proof.jwt`) signed by the issuer key.

### Current behavior (verifier)

- Verifier fetches the status list URL and validates:
  - same origin relative to `ISSUER_SERVICE_BASE_URL`
  - required path prefix `/status-lists/`
  - production HTTPS + blocks IP literals/private hosts
  - signature on `proof.jwt` using issuer JWKS
- It then checks the bit at `statusListIndex` inside `credentialSubject.encodedList`.

### Decision to make explicit

This is internally consistent, but ecosystems differ on how SD-JWT VC revocation should be expressed. To keep compatibility intentional, pick one:

- **Primary: Token-style status list** (SD-JWT VC status mechanism) and optionally publish a W3C translation for other ecosystems; OR
- **Primary: W3C Bitstring profile** and make the SD-JWT `status` claim explicitly profile-namespaced (so it is not “spec-shaped but different”).

### Privacy posture for status list retrieval

The current verifier SSRF protections are strong, but they also pin retrieval to the issuer origin. If you want to move status list hosting behind a dedicated domain/CDN later, treat it as a deliberate profile decision (explicit allowlisted origin(s) with the same SSRF rules).

## C) DID Control + Rotation Trust Contract (Needs a Stated Model)

The repo implements wallet-driven signing for DID operations (request/submit), but DID-method semantics need an explicit “compatibility target” statement:

- What key(s) are authoritative for DID updates/deactivation?
- What does “rotate root key” mean without changing the DID identifier?
- What does recovery authorize relative to update authorization?

This statement should match:

- wallet-cli rotation/recovery flows
- did-service update authorization checks (via SDK/resolver)
- verifier DID key binding assumptions (authorized keys extracted from DID document)

## D) ZK Statement Trust Contract (Soundness vs Meaning)

### What is strong already

- Proof verification is registry-driven: statement definitions declare required bindings, public inputs order, parameter constraints, and allowed commitment schemes.
- Proofs are bound to request context via `nonce/audience/request_hash` public inputs and drift bounds.

### The gap to label explicitly

For `age_credential_v1`, the wallet computes `dob_commitment` locally and sends it as a claim; the issuer enforces a shape/allowed-claims contract and explicitly forbids DOB fields.

That means the current trust contract is:

- **cryptographically sound proof**
- but **self-asserted attribute behind the commitment** (issuer does not verify DOB-derived truth)

If downstream policy treats “age >= 18” as high assurance, the ZK statement registry should grow an explicit “attestation level” field per statement/credential (e.g., self_asserted vs issuer_attested vs third_party_attested), and policies should be able to require a minimum assurance level.

## E) Aura Trust Contract (Sybil vs Collusion)

The Aura scoring layer includes meaningful anti-collusion primitives (caps, decay, diversity constraints). The remaining high-leverage decision is domain-specific **Sybil posture**:

- Which Aura domains are sybil-sensitive?
- What makes a counterparty eligible to generate weight (credential requirement, stake/cost, tier floors, etc.)?

Treat this as a trust contract per domain (policy + enforcement), not just “more math.”
