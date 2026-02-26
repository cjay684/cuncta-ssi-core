# Key Recovery (Non-Custodial)

This runbook documents the minimal, customer-ready recovery story for CUNCTA SSI Core:
recovery is performed by the holder via a normal DID update (key rotation). There is no
custodial override and no server-side storage of user secrets.

## What This Is

- A holder-controlled recovery key can rotate the holder DID keys after the primary key is lost.
- The recovery key is installed onto the DID while the primary key still exists.
- Rotation is Hedera-only (DID method: `did:hedera:*`).

## What This Is Not

- Not a helpdesk reset / admin override.
- Not a social-custody “we can recover your account” mechanism.
- Not a hardware wallet integration (those remain optional, app-specific, and behind flags).

## Threat Assumptions

- The recovery key is higher-privilege than the day-to-day primary key.
- Store the recovery key separately (offline if possible) and protect it with strong OS controls.
- If an attacker obtains the recovery key, they can rotate the DID and impersonate the holder.

## Workflow (wallet-cli demo)

Prereqs:

- `HEDERA_NETWORK=testnet` for demos (mainnet is opt-in).
- Self-funded payer creds available (`HEDERA_PAYER_ACCOUNT_ID`, `HEDERA_PAYER_PRIVATE_KEY`), or operator fallback is allowed only in testnet/dev.
- `DID_SERVICE_BASE_URL` points to a reachable did-service for resolution checks.

### 1) Create a DID (primary key)

```powershell
pnpm --filter wallet-cli dev -- did:create:auto --mode user_pays
```

### 2) Install a recovery key onto the DID

This provisions a dedicated recovery key in the configured wallet keystore and publishes a DID update
that adds the recovery key as an authorized verification method. No recovery private key material is
stored in plaintext on disk in the production-ready keystore modes.

```powershell
pnpm --filter wallet-cli dev -- did:recovery:setup
```

### 3) Simulate losing the primary key locally

This removes the primary key from `wallet-state.json` without changing the DID.

```powershell
pnpm --filter wallet-cli dev -- did:recovery:simulate-loss
```

### 4) Rotate the DID using the recovery key

This performs a standard DID update signed by the recovery key:
- Adds a fresh primary key
- Removes the previous primary verification method (best-effort)
- Updates `wallet-state.json` to the new primary key

Cooldown behavior:

- In production posture (`NODE_ENV=production`), recovery rotation enforces a cooldown before it can run.
- Configure via `RECOVERY_COOLDOWN_SECONDS` (default: 3600 seconds in production).
- This is intended to reduce “instant takeover” risk if a recovery key is compromised.

```powershell
pnpm --filter wallet-cli dev -- did:recovery:rotate
```

### 5) Verify holder binding still works

Run any wallet presentation/verification flow that relies on KB-JWT holder binding.

## Operational Notes

- No secrets are sent to servers; only signatures are submitted.
- Servers remain fail-closed in production posture (misconfig should deny).
- The recovery key install step is intentionally explicit and auditable.
- On compromise: if you suspect the recovery key is exposed, rotate it immediately (install a new recovery key and remove the old verification method).

