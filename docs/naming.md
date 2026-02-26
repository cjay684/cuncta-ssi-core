# Social v0.7 Naming Map

This document separates canonical user-facing names from internal action IDs and legacy aliases.

## Canonical user-facing terms

- Hangout (preferred user term for live voice room control-plane)
- Challenges (preferred UI term replacing Rituals)
- Rankings / Top Contributors (preferred UI labels replacing Leaderboard)
- Crew (micro-tribe inside a Space)

## Internal identifiers (stable)

- `sync.huddle.*` remains valid and supported
- `ritual.*` remains valid and supported
- `/v1/social/spaces/:spaceId/leaderboard` remains valid and supported

## Legacy aliases and compatibility

- Legacy term: Huddle
  - Legacy routes remain: `/v1/social/sync/huddle/*`
  - Preferred routes added: `/v1/social/sync/hangout/*`
  - Action aliases added: `sync.hangout.create_session|join_session|end_session`
  - Both families map to the same capabilities/policies and control-plane behavior

- Legacy term: Ritual
  - Legacy routes remain: `/v1/social/ritual/*`, `/v1/social/spaces/:spaceId/rituals/active`
  - Preferred UI label is Challenges
  - New recurring API surface: `/v1/social/spaces/:spaceId/challenges`, `/v1/social/challenges/:challengeId/*`
  - Internal namespace remains `ritual.*` for backward compatibility

- Legacy term: Leaderboard
  - Legacy route remains: `/v1/social/spaces/:spaceId/leaderboard`
  - Preferred UI labels are Rankings / Top Contributors
  - Variant added: `/v1/social/spaces/:spaceId/rankings?type=contributors|streaks`

## New Social v0.7 entities

- Crew routes:
  - `POST /v1/social/spaces/:spaceId/crews`
  - `GET /v1/social/spaces/:spaceId/crews`
  - `POST /v1/social/crews/:crewId/join`
  - `POST /v1/social/crews/:crewId/invite`
  - `POST /v1/social/crews/:crewId/leave`
  - `GET /v1/social/crews/:crewId/presence`

- Challenge + streak routes:
  - `GET /v1/social/spaces/:spaceId/challenges`
  - `POST /v1/social/spaces/:spaceId/challenges`
  - `POST /v1/social/challenges/:challengeId/join`
  - `POST /v1/social/challenges/:challengeId/complete`
  - `GET /v1/social/spaces/:spaceId/streaks`
