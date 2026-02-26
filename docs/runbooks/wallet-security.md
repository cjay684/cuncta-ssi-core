# Wallet Key Security

This repo supports multiple wallet key storage modes. The goal is to keep wallet private keys off disk in plaintext and ensure production runs fail closed on insecure key storage.

## Modes

### `WALLET_KEYSTORE=file` (development only)

- Stores Ed25519 private keys in the local wallet state JSON file in plaintext (`wallet-state.json`).
- Intended for local development and CI only.
- Production behavior: **disabled by default**.

Enable explicitly (not recommended):

- `ALLOW_INSECURE_WALLET_KEYS=true`

### `WALLET_KEYSTORE=dpapi` (production-ready on Windows)

- Windows-only.
- Stores Ed25519 private keys encrypted using Windows DPAPI (Current User scope).
- Private key material is persisted only as a DPAPI-protected blob; signing operations decrypt in-process for signing.

Threat assumptions:

- Protects keys at rest against offline disk theft and casual file exfiltration.
- Does not protect against a fully compromised logged-in user session (malware running as the same user can request signing).

## Operational guidance

- Prefer `WALLET_KEYSTORE=dpapi` on Windows desktop deployments.
- Keep `WALLET_KEYSTORE=file` for development only and gate it behind `ALLOW_INSECURE_WALLET_KEYS=true` if you must run it in a production-like environment.

## What the wallet stores

- Wallet state (`wallet-state.json`) may store:
  - DID (`did:...`) and credential material (as issued to the holder)
  - holder public key (for `cnf.jwk`)
  - keystore-encrypted private key blobs (DPAPI mode) under a dedicated `keystore` bucket
- No raw private key material is stored server-side by any service.

