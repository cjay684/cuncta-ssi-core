# Policy Version Floor

`policy_version_floor` prevents runtime downgrade to older signed policies.

## Behavior

- A floor is stored per `action_id`.
- Verifier denies with `policy_version_downgrade` when pinned policy version is below floor.
- Policy service initializes missing floors to latest enabled policy version at startup when `POLICY_VERSION_FLOOR_ENFORCED=true`.

## Operator override

Use internal policy endpoint with service auth scope `policy:floor_set`:

- `POST /v1/internal/policy/floor`
- body: `{ "actionId": "<action>", "minVersion": <int> }`

Use this only for controlled rollout/migration steps.
