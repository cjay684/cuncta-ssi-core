# Social MVP Contract

This document defines the canonical, user-visible behavior contract for Social MVP on Hedera Testnet.

Scope:

- additive product behavior only;
- no change to SSI semantics;
- no change to trust guarantees (SD-JWT, KB-JWT holder binding, policy floor/pinning, revocation, DSR, anchoring);
- no runtime mocks/stubs.

## 1) Onboarding (user-pays)

User-visible contract:

- Primary path is user-pays onboarding on holder-controlled devices.
- Wallet connector path is attempted first (HashPack first-class); local SDK key entry is demo-only fallback.
- Identity creation completes only after DID visibility is confirmed.
- No backend custody of holder private keys.

Correctness signal:

- user obtains a usable DID and can continue to policy-gated social actions.

## 2) Profile create

User-visible contract:

- `social.profile.create` is policy-gated and returns clear ALLOW/DENY.
- Successful create returns a profile identifier.
- Denied create explains that required capability/proof is missing or restricted.

Correctness signal:

- policy decision and profile create result are consistent for the same proof/challenge.

## 3) Post / reply / follow

User-visible contract:

- `social.post.create`, `social.reply.create`, and `social.follow.create` are all policy-gated.
- Each action returns ALLOW/DENY and user-readable messaging.
- Feed remains readable under normal and restricted states.

Correctness signal:

- successful actions appear as expected in user-facing flow;
- denied actions are blocked consistently with policy/DSR state.

## 4) Aura tiers

User-visible contract:

- Aura progression is derived from verified social outcomes.
- Capability credentials (for example `cuncta.social.can_post`, `cuncta.social.trusted_creator`) can be claimed when eligible.
- Explain output describes rationale in user-facing terms.

Correctness signal:

- users see current capability/tier state and explanation path, without exposing internal queue mechanics.

## 5) Restrict semantics

User-visible contract:

- Restrict disables new write actions for the restricted subject.
- Read access to feed remains available.

Correctness signal:

- write attempts are denied after restrict;
- feed read remains successful.

## 6) Erase semantics

User-visible contract:

- Erase/unlink removes subject content from normal feed visibility.
- New writes for erased subject remain denied.
- On-chain anchors remain immutable; erase applies to off-chain linkable/social output.

Correctness signal:

- erased subject content is excluded from feed;
- post/follow/reply writes are denied after erase.

## 7) Integration termination conditions (canonical)

The SOCIAL_MODE integration is considered correct only when all conditions hold:

1. End-to-end social flow completes (onboarding -> profile -> post/reply/follow/report -> DSR restrict -> DSR erase checks).
2. All waits are bounded (timeout + poll interval + timeout diagnostics).
3. Final user-visible correctness checks pass:
   - restrict denies writes while feed remains readable;
   - erase excludes content from feed and denies writes.
4. Harness exits with code `0`.
5. All spawned services stop cleanly.
6. Required ports are closed after shutdown.

## 8) Contract principle

Internal DB flags, row status fields, and worker intermediate states are implementation details.

Canonical correctness is defined by user-visible and API-visible outcomes:

- policy ALLOW/DENY behavior,
- feed visibility behavior,
- DSR behavior,
- deterministic integration completion and clean shutdown.
