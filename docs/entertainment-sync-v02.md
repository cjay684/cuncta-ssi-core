# Entertainment Layer v0.2 Sync Sessions

This change introduces real-time control-plane Sync Sessions for:

- Scroll Groups (`sync_sessions.kind = "scroll"`)
- Listen Groups (`sync_sessions.kind = "listen"`)

## API

- REST control-plane endpoints are proxied through `app-gateway` under `/v1/social/sync/...`.
- WebSocket stream endpoint is implemented in `social-service` at:
  - `GET /v1/social/sync/session/:sessionId/stream?permission_token=...`

## Gateway WS posture

- Current gateway stack proxies REST routes for sync sessions.
- WebSocket upgrade proxying is not enabled in this patch.
- In dev/internal network, connect directly to `social-service` stream endpoint.
- Production expectation remains gateway-fronted WS proxying as a follow-up hardening step.
