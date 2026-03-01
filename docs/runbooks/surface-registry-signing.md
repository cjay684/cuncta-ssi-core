# Surface Registry Signing Runbook

This repo treats `docs/surfaces.registry.json` as security-critical configuration. In production posture (`NODE_ENV=production` + `PUBLIC_SERVICE=true`), `app-gateway` and `issuer-service` fail closed at startup if the signed surface registry bundle cannot be verified.

## Deterministic Signing Model

The surface registry bundle is a signed JWS (compact form) wrapped in a JSON file:

- The signed payload is the **canonical JSON bytes** of `docs/surfaces.registry.json`.
- Canonicalization is deterministic:
  - Objects: keys are sorted recursively
  - Arrays: order is preserved (registry author controls route ordering)
  - Serialization: no whitespace differences (plain `JSON.stringify` on the canonical structure)
- The JWS protected header is deterministic and contains only:
  - `alg: "EdDSA"`
  - `typ: "surface-registry+json"`
  - `kid: <public JWK kid>` (no timestamps like `iat`)
  - `canon: 1` (canonicalization version pin; part of the signature)

This guarantees the committed `docs/surfaces.registry.bundle.json` cannot drift silently:

- If the registry changes, the bundle payload no longer matches and verification fails.
- If the bundle file is manually edited (even “cosmetic” edits), CI rewrites it deterministically and fails on `git diff`.

## Files

- Unsigned source of truth: `docs/surfaces.registry.json`
- Signed bundle (committed): `docs/surfaces.registry.bundle.json`
- Signing/verification script: `scripts/security/sign-surface-registry.mjs`

## Canonicalization Version Pinning (`canon`)

The protected header includes a short `canon` integer that pins the canonicalization rules used to produce the signed payload bytes. This prevents silent breakage if canonicalization logic changes in the future.

Optional (informational-only) visibility: you may also add a top-level field to `docs/surfaces.registry.json`, e.g. `"canonicalizationVersion": 1`, so humans can see the expected version at a glance. This is not used for verification (verification is based on the signed protected header), but it is still part of the signed payload bytes, so changing it requires re-signing the bundle.

Rules:

- `canon` is included in the protected header and therefore covered by the signature.
- Verification fails if the bundle’s `canon` does not match the local pinned version.
- Unknown protected header fields are rejected (fail closed).
- Backwards-compat: bundles created before `canon` existed are treated as `canon=1` while the local pinned version is still `1`.

## Migration Safeguard (When Canonicalization Changes)

If (and only if) canonicalization logic ever changes:

1. Increment the pinned version intentionally:
   - `scripts/security/sign-surface-registry.mjs`: `CANON_VERSION`
   - `packages/shared/src/surfaceRegistry.ts`: `SURFACE_REGISTRY_CANON_VERSION`
2. Expect verification to fail with:
   - `surface_registry_canonicalization_version_mismatch`
3. Re-sign the bundle with the new version (no auto-repair):
   - `SURFACE_REGISTRY_PRIVATE_KEY='...' SURFACE_REGISTRY_PUBLIC_KEY='...' node scripts/security/sign-surface-registry.mjs`
4. Commit the updated `docs/surfaces.registry.bundle.json` and deploy.

Explicit instruction: bump `canon` only as a deliberate, reviewed migration step. Never allow canonicalization changes to ship “implicitly” without a version bump and a fresh re-sign.

## Environment Variables

- `SURFACE_REGISTRY_PUBLIC_KEY` (required in production)
  - Base64url-encoded JWK JSON (public key)
- `SURFACE_REGISTRY_PRIVATE_KEY` (required only when signing)
  - Base64url-encoded JWK JSON (private key; includes `d`)
  - Do not commit this value to git

## Generate A New Ed25519 Keypair

Requires Node + the repo’s existing `jose` dependency.

`kid` naming guidance:

- Production: do NOT use `*-dev-*` (example bad: `surface-registry-dev-1`).
- Use an explicit production identifier (examples: `surface-registry-prod-1`, `surface-registry-prod-2026-01`).

```bash
node -e "(async()=>{const { generateKeyPair, exportJWK } = await import('jose'); const { publicKey, privateKey } = await generateKeyPair('EdDSA'); const pub = await exportJWK(publicKey); const priv = await exportJWK(privateKey); pub.alg='EdDSA'; pub.kid='surface-registry-1'; priv.alg='EdDSA'; priv.kid='surface-registry-1'; console.log('SURFACE_REGISTRY_PUBLIC_KEY=' + Buffer.from(JSON.stringify(pub),'utf8').toString('base64url')); console.log('SURFACE_REGISTRY_PRIVATE_KEY=' + Buffer.from(JSON.stringify(priv),'utf8').toString('base64url')); })().catch(e=>{console.error(e);process.exit(1);});"
```

Store `SURFACE_REGISTRY_PRIVATE_KEY` in your secrets manager (CI secret, build secret, or offline signing machine), not in the repo.

## Sign The Registry

After modifying `docs/surfaces.registry.json`:

```bash
SURFACE_REGISTRY_PRIVATE_KEY='...' SURFACE_REGISTRY_PUBLIC_KEY='...' node scripts/security/sign-surface-registry.mjs
```

This writes `docs/surfaces.registry.bundle.json`. Commit the updated bundle along with the registry changes.

Tip: if you only need to normalize the bundle’s deterministic formatting (no signing), you can run:

```bash
SURFACE_REGISTRY_PUBLIC_KEY='...' node scripts/security/sign-surface-registry.mjs --sync
```

## CI Verification

CI runs:

- `node scripts/security/surface-scan.mjs` (parity: docs ↔ registry ↔ code)
- `node scripts/security/sign-surface-registry.mjs --verify` (bundle ↔ registry + signature verification)
- `node scripts/security/sign-surface-registry.mjs --sync` + `git diff --exit-code docs/surfaces.registry.bundle.json` (deterministic bytes guard)
- `node scripts/security/surface-registry-drift.test.mjs` (simulated drift must fail)

CI does not require the private key.

## Common CI Errors

- `surface_registry_bundle_registry_mismatch`
  - The unsigned registry (`docs/surfaces.registry.json`) changed, but the committed bundle was not updated.
  - Fix: re-sign the registry (see “Sign The Registry”) and commit both files.
- `surface_registry_bundle_not_deterministic`
  - The bundle file bytes are not the deterministic serialization the repo expects (typically manual edits or a non-canonical rewrite).
  - Fix: run `node scripts/security/sign-surface-registry.mjs --sync` and commit the updated bundle.
- `surface_registry_integrity_failed`
  - Signature verification failed, or the payload/header failed strict integrity checks.
  - Fix: treat as security-sensitive; re-sign with the correct key (or rotate keys if compromise is suspected).

## Key Rotation Procedure

1. Generate a new keypair.
2. Update the production deployment configuration:
   - Set `SURFACE_REGISTRY_PUBLIC_KEY` to the new public key value.
3. Re-sign the registry and commit:
   - `SURFACE_REGISTRY_PRIVATE_KEY` = new private key
   - Run `scripts/security/sign-surface-registry.mjs`
4. Deploy services and roll restart.

If you need a grace period for rotation, plan a coordinated deployment (old bundle verifies with old key; new bundle verifies with new key) and switch the bundle + env var together.

## Incident Response (Registry Compromise)

If you suspect `docs/surfaces.registry.bundle.json` or `docs/surfaces.registry.json` was tampered with:

1. Treat it as a production security incident (route exposure risk).
2. Immediately rotate keys:
   - Generate new keypair
   - Update `SURFACE_REGISTRY_PUBLIC_KEY` in production
   - Re-sign and commit a new bundle
3. Audit:
   - Review recent changes touching `docs/surfaces.registry*.json`
   - Re-run CI security gates locally
4. Redeploy and verify services fail closed without the correct key.

## Emergency Recovery Procedure (Signing Key Compromise)

If the private signing key (`SURFACE_REGISTRY_PRIVATE_KEY`) is suspected compromised:

1. Rotate keys immediately (generate a new Ed25519 keypair).
2. Re-sign the current registry with the new private key and commit the new bundle.
3. Update production `SURFACE_REGISTRY_PUBLIC_KEY` to the new public key and roll restart services.
4. Verify:
   - Production fails closed if the public key is missing/incorrect.
   - CI `--verify` passes for the new bundle and fails for the old key.
5. Incident follow-up:
   - Confirm the old key is revoked/removed from all secret stores.
   - Review git history + deployment logs for unauthorized route exposure.
