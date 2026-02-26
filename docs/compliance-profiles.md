# Compliance Profiles (UK/EU) — Data-Driven

Core principle: jurisdiction-aware behavior is expressed as data (profiles + maps), not hardcoded
`if/else` branches per endpoint.

## What A Profile Is

A profile is a small overlay with strict, fail-closed flags and optional “tightening” rules that can
only make requirements stricter.

Built-in profiles (shipped in `@cuncta/policy-profiles`):

- `default`
- `uk`
- `eu`

Profiles live under:

- `packages/policy-profiles/profiles/*.json`

## How A Profile Is Selected

Selection order:

1) Explicit `context.profile_id` (request context)
2) `context.verifier_origin` origin → `COMPLIANCE_PROFILE_ORIGIN_MAP_JSON` mapping
3) `COMPLIANCE_PROFILE_DEFAULT` fallback

No endpoint-specific jurisdiction logic is used.

## What Profiles Can Change

Profiles can:

- Tighten binding requirements (e.g. require KB-JWT binding)
- Tighten revocation requirements (e.g. force revocation required)
- Set verifier enforcement flags (e.g. origin audience enforcement)

Profiles cannot loosen requirements.

## Service Integration

- `policy-service` applies the selected profile overlay when generating requirements.
- `verifier-service` also selects the profile locally and enforces profile flags (defense in depth),
  including for pinned-policy verification paths.

## Configuration

Common env knobs:

- `COMPLIANCE_PROFILE_DEFAULT=default|uk|eu`
- `COMPLIANCE_PROFILE_ORIGIN_MAP_JSON='{"https://rp.example":"uk"}'`

