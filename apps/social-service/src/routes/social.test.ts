import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createHmacSha256Pseudonymizer } from "@cuncta/shared";

process.env.NODE_ENV = "development";
process.env.ALLOW_INSECURE_DEV_AUTH = "true";
process.env.PSEUDONYMIZER_PEPPER = process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456";
process.env.APP_GATEWAY_BASE_URL = process.env.APP_GATEWAY_BASE_URL ?? "http://localhost:3010";
process.env.ISSUER_SERVICE_BASE_URL =
  process.env.ISSUER_SERVICE_BASE_URL ?? "http://localhost:3002";
process.env.SERVICE_JWT_SECRET =
  process.env.SERVICE_JWT_SECRET ?? "test-social-secret-012345678901234567890123";
process.env.SERVICE_JWT_SECRET_ISSUER =
  process.env.SERVICE_JWT_SECRET_ISSUER ?? "test-issuer-secret-012345678901234567890123";

const makeJsonResponse = (payload: unknown, status = 200) =>
  new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" }
  });

test("social post denies when verify decision is DENY", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/internal/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: false });
    }
    if (url.includes("/v1/requirements")) {
      return makeJsonResponse({ requirements: [{ vct: "cuncta.social.account_active" }] });
    }
    if (url.includes("/v1/verify")) {
      return makeJsonResponse({ decision: "DENY", reasons: ["predicate_failed"] });
    }
    return makeJsonResponse({}, 404);
  }) as typeof fetch;

  const { buildServer } = await import("../server.js");
  const app = buildServer();
  await app.ready();
  const response = await app.inject({
    method: "POST",
    url: "/v1/social/post",
    payload: {
      subjectDid: "did:hedera:testnet:subject:1",
      content: "hello world",
      visibility: "public",
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-social-post-12345",
      audience: "cuncta.action:social.post.create"
    }
  });
  assert.equal(response.statusCode, 403);
  const payload = response.json() as { decision?: string };
  assert.equal(payload.decision, "DENY");
  await app.close();
  globalThis.fetch = originalFetch;
});

test("space join denies on pinned policy hash mismatch", async () => {
  const originalFetch = globalThis.fetch;
  let verifyCalled = false;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/internal/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: false });
    }
    if (url.includes("/v1/requirements")) {
      return makeJsonResponse({
        requirements: [{ vct: "cuncta.social.space.member" }],
        policyHash: "runtime-policy-hash"
      });
    }
    if (url.includes("/v1/verify")) {
      verifyCalled = true;
      return makeJsonResponse({ decision: "ALLOW" });
    }
    return makeJsonResponse({}, 404);
  }) as typeof fetch;

  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");
  const db = await getDb();
  const app = buildServer();
  await app.ready();

  const spaceId = randomUUID();
  const now = new Date().toISOString();
  await db("social_space_policy_packs")
    .insert({
      policy_pack_id: "space.test.policy-pack",
      display_name: "Test space pack",
      join_action_id: "social.space.join",
      post_action_id: "social.space.post.create",
      moderate_action_id: "social.space.moderate",
      visibility: "members",
      join_policy_hash: "pinned-policy-hash",
      post_policy_hash: "pinned-policy-hash",
      moderate_policy_hash: "pinned-policy-hash",
      pinned_policy_hash_join: "pinned-policy-hash",
      pinned_policy_hash_post: "pinned-policy-hash",
      pinned_policy_hash_moderate: "pinned-policy-hash",
      created_at: now,
      updated_at: now
    })
    .onConflict("policy_pack_id")
    .merge({ pinned_policy_hash_join: "pinned-policy-hash", updated_at: now });
  await db("social_spaces")
    .insert({
      space_id: spaceId,
      slug: `space-hash-mismatch-${spaceId.slice(0, 8)}`,
      display_name: "Mismatch Space",
      description: "test",
      created_by_subject_did_hash: "subject-hash",
      policy_pack_id: "space.test.policy-pack",
      created_at: now
    })
    .onConflict("space_id")
    .ignore();

  const response = await app.inject({
    method: "POST",
    url: "/v1/social/space/join",
    payload: {
      subjectDid: "did:hedera:testnet:subject:policy-pack-mismatch",
      spaceId,
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-space-join-12345",
      audience: "cuncta.action:social.space.join"
    }
  });

  assert.equal(response.statusCode, 403);
  const payload = response.json() as { error?: string; message?: string };
  assert.equal(payload.error, "policy_pack_hash_mismatch");
  assert.equal(payload.message, "Space rules updated; please refresh.");
  assert.equal(verifyCalled, false);

  await db("social_spaces").where({ space_id: spaceId }).del();
  await db("social_space_policy_packs").where({ policy_pack_id: "space.test.policy-pack" }).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("privacy tombstone blocks social action before verify", async () => {
  const originalFetch = globalThis.fetch;
  let verifyCalled = false;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/internal/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: true });
    }
    if (url.includes("/v1/verify")) {
      verifyCalled = true;
      return makeJsonResponse({ decision: "ALLOW" });
    }
    return makeJsonResponse({}, 404);
  }) as typeof fetch;

  const { buildServer } = await import("../server.js");
  const app = buildServer();
  await app.ready();
  const response = await app.inject({
    method: "POST",
    url: "/v1/social/profile/create",
    payload: {
      subjectDid: "did:hedera:testnet:subject:2",
      handle: "alice",
      displayName: "Alice",
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-social-profile-12345",
      audience: "cuncta.action:social.profile.create"
    }
  });
  assert.equal(response.statusCode, 403);
  assert.equal(verifyCalled, false);
  await app.close();
  globalThis.fetch = originalFetch;
});

test("restricted account cannot write but can read feed", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/internal/privacy/status")) {
      return makeJsonResponse({ restricted: true, tombstoned: false });
    }
    if (url.includes("/v1/requirements")) {
      return makeJsonResponse({ requirements: [{ vct: "cuncta.social.account_active" }] });
    }
    if (url.includes("/v1/verify")) {
      return makeJsonResponse({ decision: "ALLOW" });
    }
    return makeJsonResponse({}, 404);
  }) as typeof fetch;
  const { buildServer } = await import("../server.js");
  const app = buildServer();
  await app.ready();

  const denyWrite = await app.inject({
    method: "POST",
    url: "/v1/social/follow",
    payload: {
      subjectDid: "did:hedera:testnet:subject:3",
      followeeDid: "did:hedera:testnet:subject:9",
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-social-follow-12345",
      audience: "cuncta.action:social.follow.create"
    }
  });
  assert.equal(denyWrite.statusCode, 403);

  const readFeed = await app.inject({
    method: "GET",
    url: "/v1/social/feed?viewerDid=did%3Ahedera%3Atestnet%3Asubject%3A3"
  });
  assert.equal(readFeed.statusCode, 200);

  await app.close();
  globalThis.fetch = originalFetch;
});

test("funnel counts attempts and denied decisions", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/internal/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: false });
    }
    if (url.includes("/v1/requirements")) {
      return makeJsonResponse({ requirements: [{ vct: "cuncta.social.can_post" }] });
    }
    if (url.includes("/v1/verify")) {
      return makeJsonResponse({ decision: "DENY", reasons: ["policy_failed"] });
    }
    return makeJsonResponse({}, 404);
  }) as typeof fetch;
  const { buildServer } = await import("../server.js");
  const app = buildServer();
  await app.ready();

  await app.inject({
    method: "POST",
    url: "/v1/social/post",
    payload: {
      subjectDid: "did:hedera:testnet:subject:4",
      content: "first post",
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-social-post-67890",
      audience: "cuncta.action:social.post.create"
    }
  });
  const funnel = await app.inject({ method: "GET", url: "/v1/social/funnel" });
  const body = funnel.json() as {
    funnel: Record<
      string,
      { attempts: number; denied: number; allowed: number; completed: number }
    >;
  };
  assert.ok((body.funnel.post?.attempts ?? 0) >= 1);
  assert.ok((body.funnel.post?.denied ?? 0) >= 1);

  await app.close();
  globalThis.fetch = originalFetch;
});

test("space rules preview returns friendly requirements without policy hashes", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/requirements")) {
      if (url.includes("social.space.join")) {
        return makeJsonResponse({
          requirements: [{ vct: "cuncta.social.space.member", label: "Space member capability" }]
        });
      }
      if (url.includes("social.space.post.create")) {
        return makeJsonResponse({
          requirements: [{ vct: "cuncta.social.space.poster", label: "Space poster capability" }]
        });
      }
      if (url.includes("social.space.moderate")) {
        return makeJsonResponse({
          requirements: [
            { vct: "cuncta.social.space.moderator", label: "Space moderator capability" }
          ]
        });
      }
    }
    return makeJsonResponse({}, 404);
  }) as typeof fetch;

  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");
  const db = await getDb();
  const app = buildServer();
  await app.ready();
  const spaceId = randomUUID();
  const now = new Date().toISOString();
  await db("social_space_policy_packs")
    .insert({
      policy_pack_id: "space.rules-test.policy-pack",
      display_name: "Rules test pack",
      join_action_id: "social.space.join",
      post_action_id: "social.space.post.create",
      moderate_action_id: "social.space.moderate",
      visibility: "members",
      join_policy_hash: "join-hash",
      post_policy_hash: "post-hash",
      moderate_policy_hash: "moderate-hash",
      pinned_policy_hash_join: "join-hash",
      pinned_policy_hash_post: "post-hash",
      pinned_policy_hash_moderate: "moderate-hash",
      created_at: now,
      updated_at: now
    })
    .onConflict("policy_pack_id")
    .merge({ updated_at: now });
  await db("social_spaces")
    .insert({
      space_id: spaceId,
      slug: `space-rules-${spaceId.slice(0, 8)}`,
      display_name: "Rules Space",
      description: "rules test",
      created_by_subject_did_hash: "subject-hash",
      policy_pack_id: "space.rules-test.policy-pack",
      created_at: now
    })
    .onConflict("space_id")
    .ignore();

  const response = await app.inject({
    method: "GET",
    url: `/v1/social/spaces/${spaceId}/rules`
  });
  assert.equal(response.statusCode, 200);
  const payload = response.json() as {
    join_requirements?: Array<{ vct: string; label: string }>;
    post_requirements?: Array<{ vct: string; label: string }>;
    moderation_requirements?: Array<{ vct: string; label: string }>;
    policy_pack?: { policy_pack_id?: string };
    join_policy_hash?: string;
  };
  assert.equal(payload.policy_pack?.policy_pack_id, "space.rules-test.policy-pack");
  assert.ok((payload.join_requirements?.length ?? 0) > 0);
  assert.ok((payload.post_requirements?.length ?? 0) > 0);
  assert.ok((payload.moderation_requirements?.length ?? 0) > 0);
  assert.equal("join_policy_hash" in payload, false);

  await db("social_spaces").where({ space_id: spaceId }).del();
  await db("social_space_policy_packs")
    .where({ policy_pack_id: "space.rules-test.policy-pack" })
    .del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("moderation cases routes deny non-moderator", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/internal/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: false });
    }
    if (url.includes("/v1/requirements")) {
      return makeJsonResponse({ requirements: [{ vct: "cuncta.social.space.moderator" }] });
    }
    if (url.includes("/v1/verify")) {
      return makeJsonResponse({ decision: "DENY", reasons: ["missing_moderator_capability"] });
    }
    return makeJsonResponse({}, 404);
  }) as typeof fetch;
  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");
  const db = await getDb();
  const app = buildServer();
  await app.ready();
  const spaceId = randomUUID();
  const reportId = randomUUID();
  const caseId = randomUUID();
  const now = new Date().toISOString();
  await db("social_space_policy_packs")
    .insert({
      policy_pack_id: "space.moderation-test.policy-pack",
      display_name: "Moderation test pack",
      join_action_id: "social.space.join",
      post_action_id: "social.space.post.create",
      moderate_action_id: "social.space.moderate",
      visibility: "members",
      join_policy_hash: "join-hash",
      post_policy_hash: "post-hash",
      moderate_policy_hash: "moderate-hash",
      pinned_policy_hash_join: "join-hash",
      pinned_policy_hash_post: "post-hash",
      pinned_policy_hash_moderate: "moderate-hash",
      created_at: now,
      updated_at: now
    })
    .onConflict("policy_pack_id")
    .merge({ updated_at: now });
  await db("social_spaces")
    .insert({
      space_id: spaceId,
      slug: `space-mod-${spaceId.slice(0, 8)}`,
      display_name: "Moderation Space",
      description: "moderation test",
      created_by_subject_did_hash: "subject-hash",
      policy_pack_id: "space.moderation-test.policy-pack",
      created_at: now
    })
    .onConflict("space_id")
    .ignore();
  await db("social_reports").insert({
    report_id: reportId,
    reporter_subject_did_hash: "subject-hash",
    space_id: spaceId,
    reason_code: "abuse",
    created_at: now
  });
  await db("social_space_moderation_cases").insert({
    case_id: caseId,
    space_id: spaceId,
    report_id: reportId,
    status: "OPEN",
    created_at: now,
    updated_at: now
  });

  const deniedList = await app.inject({
    method: "GET",
    url: `/v1/social/spaces/${spaceId}/moderation/cases?subjectDid=did%3Ahedera%3Atestnet%3Anonmod&presentation=fake.presentation.token&nonce=nonce-moderation-list-123&audience=cuncta.action%3Asocial.space.moderate`
  });
  assert.equal(deniedList.statusCode, 403);

  const deniedResolve = await app.inject({
    method: "POST",
    url: `/v1/social/spaces/${spaceId}/moderation/cases/${caseId}/resolve`,
    payload: {
      subjectDid: "did:hedera:testnet:nonmod",
      presentation: "fake.presentation.token",
      nonce: "nonce-moderation-resolve-123",
      audience: "cuncta.action:social.space.moderate",
      anchor: false
    }
  });
  assert.equal(deniedResolve.statusCode, 403);

  await db("social_space_moderation_cases").where({ case_id: caseId }).del();
  await db("social_reports").where({ report_id: reportId }).del();
  await db("social_spaces").where({ space_id: spaceId }).del();
  await db("social_space_policy_packs")
    .where({ policy_pack_id: "space.moderation-test.policy-pack" })
    .del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("media asset moderation denies non-moderator capability", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/internal/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: false });
    }
    if (url.includes("/v1/requirements")) {
      return makeJsonResponse({ requirements: [{ vct: "cuncta.social.space.moderator" }] });
    }
    if (url.includes("/v1/verify")) {
      return makeJsonResponse({ decision: "DENY", reasons: ["missing_moderator_capability"] });
    }
    return makeJsonResponse({}, 404);
  }) as typeof fetch;
  const { buildServer } = await import("../server.js");
  const app = buildServer();
  await app.ready();
  const response = await app.inject({
    method: "POST",
    url: "/v1/social/media/asset/moderate",
    payload: {
      subjectDid: "did:hedera:testnet:nonmod",
      spaceId: randomUUID(),
      assetId: randomUUID(),
      presentation: "fake.presentation.token",
      nonce: "nonce-moderation-asset-123",
      audience: "cuncta.action:media.asset.moderate"
    }
  });
  assert.equal(response.statusCode, 403);
  const payload = response.json() as { decision?: string };
  assert.equal(payload.decision, "DENY");
  await app.close();
  globalThis.fetch = originalFetch;
});

test("tombstone unlinks entertainment subject-linked records", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/internal/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: true });
    }
    return makeJsonResponse({}, 404);
  }) as typeof fetch;
  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");
  const db = await getDb();
  const app = buildServer();
  await app.ready();
  const subjectDid = "did:hedera:testnet:tombstone-entertainment";
  const subjectHash = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  }).didToHash(subjectDid);
  const assetId = randomUUID();
  await db("media_emoji_assets").insert({
    id: assetId,
    creator_subject_hash: subjectHash,
    space_id: null,
    asset_ref: "ipfs://asset",
    hash: "hash-1",
    status: "ACTIVE",
    created_at: new Date().toISOString()
  });
  const deny = await app.inject({
    method: "POST",
    url: "/v1/social/media/emoji/create",
    payload: {
      subjectDid,
      assetRef: "ipfs://asset-2",
      presentation: "fake.presentation.token",
      nonce: "nonce-tombstone-asset-123",
      audience: "cuncta.action:media.emoji.create"
    }
  });
  assert.equal(deny.statusCode, 403);
  const stored = await db("media_emoji_assets").where({ id: assetId }).first();
  assert.ok(stored?.deleted_at);
  await db("media_emoji_assets").where({ id: assetId }).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("scroll join mints permission token only on allow", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/internal/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: false });
    }
    if (url.includes("/v1/requirements")) {
      return makeJsonResponse({ requirements: [{ vct: "cuncta.presence.mode_access" }] });
    }
    if (url.includes("/v1/verify?action=sync.scroll.create_session")) {
      return makeJsonResponse({ decision: "ALLOW" });
    }
    if (url.includes("/v1/verify?action=sync.scroll.join_session")) {
      return makeJsonResponse({ decision: "ALLOW" });
    }
    return makeJsonResponse({}, 404);
  }) as typeof fetch;
  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");
  const db = await getDb();
  const app = buildServer();
  await app.ready();

  const hostDid = "did:hedera:testnet:sync-host";
  const joinDid = "did:hedera:testnet:sync-joiner";
  const hostHash = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  }).didToHash(hostDid);
  const joinHash = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  }).didToHash(joinDid);
  const spaceId = randomUUID();
  const now = new Date().toISOString();
  await db("social_space_policy_packs")
    .insert({
      policy_pack_id: "space.sync-test.policy-pack",
      display_name: "Sync test pack",
      join_action_id: "social.space.join",
      post_action_id: "social.space.post.create",
      moderate_action_id: "social.space.moderate",
      visibility: "members",
      join_policy_hash: "join-hash",
      post_policy_hash: "post-hash",
      moderate_policy_hash: "moderate-hash",
      pinned_policy_hash_join: "join-hash",
      pinned_policy_hash_post: "post-hash",
      pinned_policy_hash_moderate: "moderate-hash",
      created_at: now,
      updated_at: now
    })
    .onConflict("policy_pack_id")
    .merge({ updated_at: now });
  await db("social_spaces").insert({
    space_id: spaceId,
    slug: `sync-space-${spaceId.slice(0, 8)}`,
    display_name: "Sync Space",
    description: "sync test",
    created_by_subject_did_hash: hostHash,
    policy_pack_id: "space.sync-test.policy-pack",
    created_at: now
  });
  await db("social_space_memberships")
    .insert([
      { space_id: spaceId, subject_did_hash: hostHash, status: "ACTIVE", joined_at: now },
      { space_id: spaceId, subject_did_hash: joinHash, status: "ACTIVE", joined_at: now }
    ])
    .onConflict(["space_id", "subject_did_hash"])
    .merge({ status: "ACTIVE", joined_at: now });

  const createResponse = await app.inject({
    method: "POST",
    url: "/v1/social/sync/scroll/create_session",
    payload: {
      subjectDid: hostDid,
      spaceId,
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-sync-create-12345",
      audience: "cuncta.action:sync.scroll.create_session"
    }
  });
  assert.equal(createResponse.statusCode, 200);
  const createPayload = createResponse.json() as { sessionId: string };
  assert.ok(createPayload.sessionId);

  const joinResponse = await app.inject({
    method: "POST",
    url: "/v1/social/sync/scroll/join_session",
    payload: {
      subjectDid: joinDid,
      sessionId: createPayload.sessionId,
      spaceId,
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-sync-join-12345",
      audience: "cuncta.action:sync.scroll.join_session"
    }
  });
  assert.equal(joinResponse.statusCode, 200);
  const joinPayload = joinResponse.json() as { permissionToken?: string };
  assert.ok(joinPayload.permissionToken);

  await db("sync_session_permissions").where({ session_id: createPayload.sessionId }).del();
  await db("sync_session_participants").where({ session_id: createPayload.sessionId }).del();
  await db("sync_sessions").where({ session_id: createPayload.sessionId }).del();
  await db("social_space_memberships").where({ space_id: spaceId }).del();
  await db("social_spaces").where({ space_id: spaceId }).del();
  await db("social_space_policy_packs")
    .where({ policy_pack_id: "space.sync-test.policy-pack" })
    .del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("scroll sync_event enforces permission expiry", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/internal/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: false });
    }
    if (url.includes("/v1/requirements")) {
      return makeJsonResponse({ requirements: [{ vct: "cuncta.presence.mode_access" }] });
    }
    if (url.includes("/v1/verify")) {
      return makeJsonResponse({ decision: "ALLOW" });
    }
    return makeJsonResponse({}, 404);
  }) as typeof fetch;
  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");
  const db = await getDb();
  const app = buildServer();
  await app.ready();

  const hostDid = "did:hedera:testnet:sync-host-2";
  const joinDid = "did:hedera:testnet:sync-joiner-2";
  const pseudo = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  });
  const hostHash = pseudo.didToHash(hostDid);
  const joinHash = pseudo.didToHash(joinDid);
  const spaceId = randomUUID();
  const now = new Date().toISOString();
  await db("social_space_policy_packs")
    .insert({
      policy_pack_id: "space.sync-test2.policy-pack",
      display_name: "Sync test pack 2",
      join_action_id: "social.space.join",
      post_action_id: "social.space.post.create",
      moderate_action_id: "social.space.moderate",
      visibility: "members",
      join_policy_hash: "join-hash",
      post_policy_hash: "post-hash",
      moderate_policy_hash: "moderate-hash",
      pinned_policy_hash_join: "join-hash",
      pinned_policy_hash_post: "post-hash",
      pinned_policy_hash_moderate: "moderate-hash",
      created_at: now,
      updated_at: now
    })
    .onConflict("policy_pack_id")
    .merge({ updated_at: now });
  await db("social_spaces").insert({
    space_id: spaceId,
    slug: `sync-space2-${spaceId.slice(0, 8)}`,
    display_name: "Sync Space 2",
    description: "sync test",
    created_by_subject_did_hash: hostHash,
    policy_pack_id: "space.sync-test2.policy-pack",
    created_at: now
  });
  await db("social_space_memberships")
    .insert([
      { space_id: spaceId, subject_did_hash: hostHash, status: "ACTIVE", joined_at: now },
      { space_id: spaceId, subject_did_hash: joinHash, status: "ACTIVE", joined_at: now }
    ])
    .onConflict(["space_id", "subject_did_hash"])
    .merge({ status: "ACTIVE", joined_at: now });

  const created = await app.inject({
    method: "POST",
    url: "/v1/social/sync/scroll/create_session",
    payload: {
      subjectDid: hostDid,
      spaceId,
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-sync-create-2",
      audience: "cuncta.action:sync.scroll.create_session"
    }
  });
  const createdPayload = created.json() as { sessionId: string };
  const joined = await app.inject({
    method: "POST",
    url: "/v1/social/sync/scroll/join_session",
    payload: {
      subjectDid: joinDid,
      sessionId: createdPayload.sessionId,
      spaceId,
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-sync-join-2",
      audience: "cuncta.action:sync.scroll.join_session"
    }
  });
  const joinedPayload = joined.json() as { permissionToken: string };
  assert.ok(joinedPayload.permissionToken);
  await db("sync_session_permissions")
    .where({ session_id: createdPayload.sessionId, subject_did_hash: joinHash })
    .update({ expires_at: new Date(Date.now() - 1000).toISOString() });

  const denied = await app.inject({
    method: "POST",
    url: "/v1/social/sync/scroll/sync_event",
    payload: {
      sessionId: createdPayload.sessionId,
      permissionToken: joinedPayload.permissionToken,
      eventType: "SCROLL_SYNC",
      payload: { scrollY: 123 }
    }
  });
  assert.equal(denied.statusCode, 403);

  await db("sync_session_permissions").where({ session_id: createdPayload.sessionId }).del();
  await db("sync_session_participants").where({ session_id: createdPayload.sessionId }).del();
  await db("sync_session_events").where({ session_id: createdPayload.sessionId }).del();
  await db("sync_sessions").where({ session_id: createdPayload.sessionId }).del();
  await db("social_space_memberships").where({ space_id: spaceId }).del();
  await db("social_spaces").where({ space_id: spaceId }).del();
  await db("social_space_policy_packs")
    .where({ policy_pack_id: "space.sync-test2.policy-pack" })
    .del();
  await app.close();
  globalThis.fetch = originalFetch;
});
