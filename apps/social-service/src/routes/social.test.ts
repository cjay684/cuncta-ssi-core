import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID, createHash } from "node:crypto";
import { createHmacSha256Pseudonymizer, hashCanonicalJson } from "@cuncta/shared";

process.env.NODE_ENV = "development";
process.env.ALLOW_INSECURE_DEV_AUTH = "true";
process.env.PSEUDONYMIZER_PEPPER = process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456";
process.env.APP_GATEWAY_BASE_URL = process.env.APP_GATEWAY_BASE_URL ?? "http://localhost:3010";
process.env.ISSUER_SERVICE_BASE_URL =
  process.env.ISSUER_SERVICE_BASE_URL ?? "http://localhost:3002";
process.env.ISSUER_PRIVACY_STATUS_TIMEOUT_MS =
  process.env.ISSUER_PRIVACY_STATUS_TIMEOUT_MS ?? "300";
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
    if (url.includes("/v1/admin/privacy/status")) {
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
    if (url.includes("/v1/admin/privacy/status")) {
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
    if (url.includes("/v1/admin/privacy/status")) {
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
    if (url.includes("/v1/admin/privacy/status")) {
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
    if (url.includes("/v1/admin/privacy/status")) {
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
    if (url.includes("/v1/admin/privacy/status")) {
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
    if (url.includes("/v1/admin/privacy/status")) {
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
    if (url.includes("/v1/admin/privacy/status")) {
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
  const mediaAssetId = randomUUID();
  await db("media_emoji_assets").insert({
    id: assetId,
    creator_subject_hash: subjectHash,
    space_id: null,
    asset_ref: "ipfs://asset",
    hash: "hash-1",
    status: "ACTIVE",
    created_at: new Date().toISOString()
  });
  await db("social_media_assets").insert({
    asset_id: mediaAssetId,
    owner_subject_hash: subjectHash,
    media_kind: "image",
    storage_provider: "s3",
    object_key: `original/${mediaAssetId}.jpg`,
    thumbnail_object_key: `thumb/${mediaAssetId}.jpg`,
    mime_type: "image/jpeg",
    byte_size: 1024,
    sha256_hex: createHash("sha256").update("media-1").digest("hex"),
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
  const storedMedia = await db("social_media_assets").where({ asset_id: mediaAssetId }).first();
  assert.equal(storedMedia?.status, "ERASED");
  assert.ok(storedMedia?.erased_at);
  await db("media_emoji_assets").where({ id: assetId }).del();
  await db("social_media_assets").where({ asset_id: mediaAssetId }).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("scroll join mints permission token only on allow", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/admin/privacy/status")) {
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
    if (url.includes("/v1/admin/privacy/status")) {
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

test("presence ping denies restricted subject", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/admin/privacy/status")) {
      return makeJsonResponse({ restricted: true, tombstoned: false });
    }
    return makeJsonResponse({}, 404);
  }) as typeof fetch;
  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");
  const db = await getDb();
  const app = buildServer();
  await app.ready();
  const subjectDid = "did:hedera:testnet:presence-restricted";
  const subjectHash = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  }).didToHash(subjectDid);
  const spaceId = randomUUID();
  const now = new Date().toISOString();
  await db("social_spaces").insert({
    space_id: spaceId,
    slug: `presence-deny-${spaceId.slice(0, 8)}`,
    display_name: "Presence Deny",
    description: "presence deny test",
    created_by_subject_did_hash: subjectHash,
    policy_pack_id: "space.default.v1",
    created_at: now
  });
  await db("social_space_memberships")
    .insert({
      space_id: spaceId,
      subject_did_hash: subjectHash,
      status: "ACTIVE",
      joined_at: now
    })
    .onConflict(["space_id", "subject_did_hash"])
    .merge({ status: "ACTIVE", joined_at: now });
  const denied = await app.inject({
    method: "POST",
    url: `/v1/social/spaces/${spaceId}/presence/ping`,
    payload: {
      subjectDid,
      mode: "active",
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-presence-ping-deny",
      audience: "cuncta.action:presence.ping"
    }
  });
  assert.equal(denied.statusCode, 403);
  await db("social_space_memberships").where({ space_id: spaceId }).del();
  await db("social_spaces").where({ space_id: spaceId }).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("presence strip returns counts and no subject hashes", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () => makeJsonResponse({}, 404)) as typeof fetch;
  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");
  const db = await getDb();
  const app = buildServer();
  await app.ready();
  const spaceId = randomUUID();
  const now = new Date().toISOString();
  await db("social_spaces").insert({
    space_id: spaceId,
    slug: `presence-view-${spaceId.slice(0, 8)}`,
    display_name: "Presence View",
    description: "presence view test",
    created_by_subject_did_hash: "subject-hash",
    policy_pack_id: "space.default.v1",
    created_at: now
  });
  await db("presence_space_states").insert([
    { space_id: spaceId, subject_hash: "hash-a", mode: "active", updated_at: now },
    { space_id: spaceId, subject_hash: "hash-b", mode: "quiet", updated_at: now }
  ]);
  await db("social_space_presence_pings").insert([
    { space_id: spaceId, subject_hash: "hash-a", last_seen_at: now },
    { space_id: spaceId, subject_hash: "hash-b", last_seen_at: now }
  ]);
  const response = await app.inject({
    method: "GET",
    url: `/v1/social/spaces/${spaceId}/presence`
  });
  assert.equal(response.statusCode, 200);
  const payload = response.json() as {
    counts?: { quiet?: number; active?: number; immersive?: number };
    states?: unknown[];
    participants?: unknown[];
  };
  assert.equal(payload.counts?.active, 1);
  assert.equal(payload.counts?.quiet, 1);
  assert.equal("states" in payload, false);
  assert.equal("participants" in payload, false);
  await db("social_space_presence_pings").where({ space_id: spaceId }).del();
  await db("presence_space_states").where({ space_id: spaceId }).del();
  await db("social_spaces").where({ space_id: spaceId }).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("huddle create and join are policy-gated", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/admin/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: false });
    }
    if (url.includes("/v1/requirements")) {
      return makeJsonResponse({ requirements: [{ vct: "cuncta.sync.huddle_host" }] });
    }
    if (url.includes("/v1/verify")) {
      return makeJsonResponse({ decision: "DENY", reasons: ["missing_huddle_host"] });
    }
    return makeJsonResponse({}, 404);
  }) as typeof fetch;
  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");
  const db = await getDb();
  const app = buildServer();
  await app.ready();
  const pseudo = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  });
  const subjectDid = "did:hedera:testnet:huddle-host";
  const subjectHash = pseudo.didToHash(subjectDid);
  const spaceId = randomUUID();
  const now = new Date().toISOString();
  await db("social_spaces").insert({
    space_id: spaceId,
    slug: `huddle-deny-${spaceId.slice(0, 8)}`,
    display_name: "Huddle Deny",
    description: "huddle deny test",
    created_by_subject_did_hash: subjectHash,
    policy_pack_id: "space.default.v1",
    created_at: now
  });
  await db("social_space_memberships").insert({
    space_id: spaceId,
    subject_did_hash: subjectHash,
    status: "ACTIVE",
    joined_at: now
  });
  const denied = await app.inject({
    method: "POST",
    url: "/v1/social/sync/huddle/create_session",
    payload: {
      subjectDid,
      spaceId,
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-huddle-create",
      audience: "cuncta.action:sync.huddle.create_session"
    }
  });
  assert.equal(denied.statusCode, 403);
  await db("social_space_memberships").where({ space_id: spaceId }).del();
  await db("social_spaces").where({ space_id: spaceId }).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("ritual lifecycle completes once and logs bounded completion", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/admin/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: false });
    }
    if (url.includes("/v1/requirements")) {
      if (url.includes("ritual.create")) {
        return makeJsonResponse({ requirements: [{ vct: "cuncta.social.space.poster" }] });
      }
      return makeJsonResponse({ requirements: [{ vct: "cuncta.social.space.member" }] });
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
  const subjectDid = `did:hedera:testnet:ritual-subject-${randomUUID().slice(0, 8)}`;
  const subjectHash = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  }).didToHash(subjectDid);
  const spaceId = randomUUID();
  const now = new Date().toISOString();
  await db("social_spaces").insert({
    space_id: spaceId,
    slug: `ritual-life-${spaceId.slice(0, 8)}`,
    display_name: "Ritual Life",
    description: "ritual lifecycle test",
    created_by_subject_did_hash: subjectHash,
    policy_pack_id: "space.default.v1",
    created_at: now
  });
  await db("social_space_memberships").insert({
    space_id: spaceId,
    subject_did_hash: subjectHash,
    status: "ACTIVE",
    joined_at: now
  });
  const created = await app.inject({
    method: "POST",
    url: "/v1/social/ritual/create",
    payload: {
      subjectDid,
      spaceId,
      title: "10-minute drop",
      description: "post now",
      durationMinutes: 10,
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-ritual-create",
      audience: "cuncta.action:ritual.create"
    }
  });
  assert.equal(created.statusCode, 200);
  const ritualId = (created.json() as { ritualId: string }).ritualId;
  const joined = await app.inject({
    method: "POST",
    url: "/v1/social/ritual/participate",
    payload: {
      subjectDid,
      ritualId,
      spaceId,
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-ritual-participate",
      audience: "cuncta.action:ritual.participate"
    }
  });
  assert.equal(joined.statusCode, 200);
  const completed = await app.inject({
    method: "POST",
    url: "/v1/social/ritual/complete",
    payload: {
      subjectDid,
      ritualId,
      spaceId,
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-ritual-complete",
      audience: "cuncta.action:ritual.complete"
    }
  });
  assert.equal(completed.statusCode, 200);
  const completedAgain = await app.inject({
    method: "POST",
    url: "/v1/social/ritual/complete",
    payload: {
      subjectDid,
      ritualId,
      spaceId,
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-ritual-complete-2",
      audience: "cuncta.action:ritual.complete"
    }
  });
  assert.equal(completedAgain.statusCode, 200);
  const logged = await db("social_action_log")
    .where({ subject_did_hash: subjectHash, action_type: "ritual.complete", decision: "COMPLETE" })
    .count<{ count: string }>("subject_did_hash as count")
    .first();
  assert.equal(Number(logged?.count ?? 0), 1);
  await db("social_space_ritual_participants").where({ ritual_id: ritualId }).del();
  await db("social_space_rituals").where({ ritual_id: ritualId }).del();
  await db("social_space_memberships").where({ space_id: spaceId }).del();
  await db("social_spaces").where({ space_id: spaceId }).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("leaderboard excludes tombstoned and respects opt-in visibility", async () => {
  const originalFetch = globalThis.fetch;
  // Use per-run unique hashes so a failed assertion doesn't poison future runs.
  const visibleHash = `hash-visible-${randomUUID()}`;
  const tombstoneHash = `hash-tombstone-${randomUUID()}`;
  const spaceId = randomUUID();
  const now = new Date().toISOString();

  type DbLike = {
    (table: string): {
      where: (query: Record<string, unknown>) => { del: () => Promise<unknown> };
      whereIn: (
        column: string,
        values: unknown[]
      ) => { where: (query: Record<string, unknown>) => { del: () => Promise<unknown> } };
      del: () => Promise<unknown>;
      insert: (value: unknown) => Promise<unknown>;
    };
  };
  type InjectResponseLike = { statusCode: number; json: () => unknown };
  type AppLike = {
    ready: () => Promise<unknown>;
    close: () => Promise<unknown>;
    inject: (opts: { method: string; url: string; payload?: unknown }) => Promise<InjectResponseLike>;
  };

  let db: DbLike | null = null;
  let app: AppLike | null = null;

  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/admin/privacy/status")) {
      const hash = new URL(url).searchParams.get("subjectDidHash");
      if (hash === tombstoneHash) {
        return makeJsonResponse({ restricted: false, tombstoned: true });
      }
      return makeJsonResponse({ restricted: false, tombstoned: false });
    }
    return makeJsonResponse({}, 404);
  }) as typeof fetch;

  try {
    const { buildServer } = (await import("../server.js")) as unknown as { buildServer: () => AppLike };
    const { getDb } = (await import("../db.js")) as unknown as { getDb: () => Promise<DbLike> };
    db = await getDb();
    app = buildServer();
    await app.ready();

    await db("social_spaces").insert({
      space_id: spaceId,
      slug: `leaderboard-${spaceId.slice(0, 8)}`,
      display_name: "Leaderboard Space",
      description: "leaderboard test",
      created_by_subject_did_hash: visibleHash,
      policy_pack_id: "space.default.v1",
      created_at: now
    });
    await db("social_action_log").insert([
      {
        subject_did_hash: visibleHash,
        action_type: "social.post.create",
        decision: "COMPLETE",
        created_at: now
      },
      {
        subject_did_hash: tombstoneHash,
        action_type: "social.post.create",
        decision: "COMPLETE",
        created_at: now
      }
    ]);
    await db("social_profiles").insert({
      profile_id: randomUUID(),
      subject_did_hash: visibleHash,
      handle_hash: `hh-${visibleHash}`,
      handle: "visible",
      display_name: "Visible User",
      created_at: now,
      updated_at: now
    });
    await db("social_space_profile_settings").insert({
      space_id: spaceId,
      subject_hash: visibleHash,
      show_on_leaderboard: true,
      show_on_presence: false,
      presence_label: "Visible User",
      updated_at: now
    });

    const response = await app.inject({
      method: "GET",
      url: `/v1/social/spaces/${spaceId}/leaderboard?window=7d`
    });
    assert.equal(response.statusCode, 200);
    const payload = response.json() as {
      top_contributors: Array<{ identity?: { displayName?: string } }>;
    };
    assert.ok(payload.top_contributors.length >= 1);
    assert.equal(
      payload.top_contributors.some((entry) => entry.identity?.displayName === "Visible User"),
      true
    );
  } finally {
    try {
      if (db) {
        await db("social_space_profile_settings").where({ space_id: spaceId }).del();
        await db("social_profiles").where({ subject_did_hash: visibleHash }).del();
        await db("social_action_log")
          .whereIn("subject_did_hash", [visibleHash, tombstoneHash])
          .where({ action_type: "social.post.create", decision: "COMPLETE" })
          .del();
        await db("social_spaces").where({ space_id: spaceId }).del();
      }
    } finally {
      await app?.close();
      globalThis.fetch = originalFetch;
    }
  }
});

test("hangout alias routes are policy-gated", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/admin/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: false });
    }
    if (url.includes("/v1/requirements")) {
      return makeJsonResponse({ requirements: [{ vct: "cuncta.sync.huddle_host" }] });
    }
    if (url.includes("/v1/verify")) {
      return makeJsonResponse({ decision: "DENY", reasons: ["missing_hangout_host"] });
    }
    return makeJsonResponse({}, 404);
  }) as typeof fetch;
  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");
  const db = await getDb();
  const app = buildServer();
  await app.ready();
  const pseudo = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  });
  const subjectDid = "did:hedera:testnet:hangout-host";
  const subjectHash = pseudo.didToHash(subjectDid);
  const spaceId = randomUUID();
  const now = new Date().toISOString();
  await db("social_spaces").insert({
    space_id: spaceId,
    slug: `hangout-deny-${spaceId.slice(0, 8)}`,
    display_name: "Hangout Deny",
    description: "hangout deny test",
    created_by_subject_did_hash: subjectHash,
    policy_pack_id: "space.default.v1",
    created_at: now
  });
  await db("social_space_memberships").insert({
    space_id: spaceId,
    subject_did_hash: subjectHash,
    status: "ACTIVE",
    joined_at: now
  });
  const denied = await app.inject({
    method: "POST",
    url: "/v1/social/sync/hangout/create_session",
    payload: {
      subjectDid,
      spaceId,
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-hangout-create",
      audience: "cuncta.action:sync.hangout.create_session"
    }
  });
  assert.equal(denied.statusCode, 403);
  await db("social_space_memberships").where({ space_id: spaceId }).del();
  await db("social_spaces").where({ space_id: spaceId }).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("crew presence returns counts only", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () => makeJsonResponse({}, 404)) as typeof fetch;
  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");
  const db = await getDb();
  const app = buildServer();
  await app.ready();
  const spaceId = randomUUID();
  const crewId = randomUUID();
  const now = new Date().toISOString();
  await db("social_spaces").insert({
    space_id: spaceId,
    slug: `crew-presence-${spaceId.slice(0, 8)}`,
    display_name: "Crew Presence",
    description: "crew presence test",
    created_by_subject_did_hash: "subject-hash",
    policy_pack_id: "space.default.v1",
    created_at: now
  });
  await db("social_space_crews").insert({
    crew_id: crewId,
    space_id: spaceId,
    name: "Alpha Crew",
    created_by_subject_hash: "subject-hash",
    created_at: now
  });
  await db("social_space_crew_members").insert([
    { crew_id: crewId, subject_hash: "hash-a", role: "captain", joined_at: now },
    { crew_id: crewId, subject_hash: "hash-b", role: "member", joined_at: now }
  ]);
  await db("social_space_presence_pings").insert([
    { space_id: spaceId, subject_hash: "hash-a", last_seen_at: now },
    { space_id: spaceId, subject_hash: "hash-b", last_seen_at: now }
  ]);
  const response = await app.inject({
    method: "GET",
    url: `/v1/social/crews/${crewId}/presence`
  });
  assert.equal(response.statusCode, 200);
  const payload = response.json() as { active_count?: number; members?: unknown[] };
  assert.equal(payload.active_count, 2);
  assert.equal("members" in payload, false);
  await db("social_space_presence_pings").where({ space_id: spaceId }).del();
  await db("social_space_crew_members").where({ crew_id: crewId }).del();
  await db("social_space_crews").where({ crew_id: crewId }).del();
  await db("social_spaces").where({ space_id: spaceId }).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("challenge completion increments daily streak after verified evidence", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/admin/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: false });
    }
    if (url.includes("/v1/requirements")) {
      return makeJsonResponse({ requirements: [{ vct: "cuncta.social.space.member" }] });
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
  const subjectDid = "did:hedera:testnet:challenge-member";
  const subjectHash = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  }).didToHash(subjectDid);
  const spaceId = randomUUID();
  const challengeId = randomUUID();
  const now = new Date().toISOString();
  await db("social_spaces").insert({
    space_id: spaceId,
    slug: `challenge-${spaceId.slice(0, 8)}`,
    display_name: "Challenge Space",
    description: "challenge streak test",
    created_by_subject_did_hash: subjectHash,
    policy_pack_id: "space.default.v1",
    created_at: now
  });
  await db("social_space_memberships").insert({
    space_id: spaceId,
    subject_did_hash: subjectHash,
    status: "ACTIVE",
    joined_at: now
  });
  await db("social_space_challenges").insert({
    challenge_id: challengeId,
    space_id: spaceId,
    cadence: "daily",
    title: "Daily drop",
    starts_at: now,
    ends_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    created_by_subject_hash: subjectHash,
    status: "ACTIVE",
    created_at: now
  });
  await db("social_space_challenge_participation").insert({
    challenge_id: challengeId,
    subject_hash: subjectHash,
    joined_at: now
  });
  await db("social_action_log").insert({
    subject_did_hash: subjectHash,
    action_type: "social.post.create",
    decision: "COMPLETE",
    created_at: now
  });
  const completed = await app.inject({
    method: "POST",
    url: `/v1/social/challenges/${challengeId}/complete`,
    payload: {
      subjectDid,
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-challenge-complete",
      audience: "cuncta.action:challenge.complete"
    }
  });
  assert.equal(completed.statusCode, 200);
  const streak = await db("social_space_streaks")
    .where({ space_id: spaceId, subject_hash: subjectHash, streak_type: "daily_challenge" })
    .first();
  assert.equal(Number(streak?.current_count ?? 0), 1);
  await db("social_space_streaks").where({ space_id: spaceId, subject_hash: subjectHash }).del();
  await db("social_space_challenge_participation").where({ challenge_id: challengeId }).del();
  await db("social_space_challenges").where({ challenge_id: challengeId }).del();
  await db("social_space_memberships").where({ space_id: spaceId }).del();
  await db("social_action_log").where({ subject_did_hash: subjectHash }).del();
  await db("social_spaces").where({ space_id: spaceId }).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("tombstone purge removes crew memberships and streak rows", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/admin/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: true });
    }
    return makeJsonResponse({}, 404);
  }) as typeof fetch;
  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");
  const db = await getDb();
  const app = buildServer();
  await app.ready();
  const subjectDid = "did:hedera:testnet:tombstone-crew-streak";
  const subjectHash = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  }).didToHash(subjectDid);
  const spaceId = randomUUID();
  const crewId = randomUUID();
  const now = new Date().toISOString();
  await db("social_spaces").insert({
    space_id: spaceId,
    slug: `tombstone-space-${spaceId.slice(0, 8)}`,
    display_name: "Tombstone Space",
    description: "tombstone test",
    created_by_subject_did_hash: subjectHash,
    policy_pack_id: "space.default.v1",
    created_at: now
  });
  await db("social_space_memberships").insert({
    space_id: spaceId,
    subject_did_hash: subjectHash,
    status: "ACTIVE",
    joined_at: now
  });
  await db("social_space_crews").insert({
    crew_id: crewId,
    space_id: spaceId,
    name: "Crew",
    created_by_subject_hash: subjectHash,
    created_at: now
  });
  await db("social_space_crew_members").insert({
    crew_id: crewId,
    subject_hash: subjectHash,
    role: "captain",
    joined_at: now
  });
  await db("social_space_streaks").insert({
    space_id: spaceId,
    subject_hash: subjectHash,
    streak_type: "daily_challenge",
    current_count: 2,
    best_count: 2,
    last_completed_at: now,
    updated_at: now
  });
  await db("social_space_pulse_preferences").insert({
    space_id: spaceId,
    subject_hash: subjectHash,
    enabled: true,
    notify_hangouts: true,
    notify_crews: true,
    notify_challenges: true,
    notify_rankings: true,
    notify_streaks: true,
    updated_at: now
  });
  const denied = await app.inject({
    method: "POST",
    url: "/v1/social/post",
    payload: {
      subjectDid,
      content: "trigger purge",
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-purge-crew-streak",
      audience: "cuncta.action:social.post.create"
    }
  });
  assert.equal(denied.statusCode, 403);
  const memberRows = await db("social_space_crew_members")
    .where({ crew_id: crewId, subject_hash: subjectHash })
    .select("subject_hash");
  const streakRows = await db("social_space_streaks")
    .where({ space_id: spaceId, subject_hash: subjectHash })
    .select("subject_hash");
  const pulsePrefRows = await db("social_space_pulse_preferences")
    .where({ space_id: spaceId, subject_hash: subjectHash })
    .select("subject_hash");
  assert.equal(memberRows.length, 0);
  assert.equal(streakRows.length, 0);
  assert.equal(pulsePrefRows.length, 0);
  await db("social_space_crews").where({ crew_id: crewId }).del();
  await db("social_space_memberships").where({ space_id: spaceId }).del();
  await db("social_spaces").where({ space_id: spaceId }).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("pulse returns crew, hangout, challenge-ending, and streak-risk cards", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/admin/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: false });
    }
    return makeJsonResponse({}, 404);
  }) as typeof fetch;
  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");
  const db = await getDb();
  const app = buildServer();
  await app.ready();
  const subjectDid = "did:hedera:testnet:pulse-main";
  const pseudo = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  });
  const subjectHash = pseudo.didToHash(subjectDid);
  const peerHash = pseudo.didToHash("did:hedera:testnet:pulse-peer");
  const spaceId = randomUUID();
  const crewId = randomUUID();
  const challengeId = randomUUID();
  const sessionId = randomUUID();
  const now = new Date().toISOString();
  await db("social_spaces").insert({
    space_id: spaceId,
    slug: `pulse-space-${spaceId.slice(0, 8)}`,
    display_name: "Pulse Space",
    description: "pulse test",
    created_by_subject_did_hash: subjectHash,
    policy_pack_id: "space.default.v1",
    created_at: now
  });
  await db("social_space_memberships").insert([
    { space_id: spaceId, subject_did_hash: subjectHash, status: "ACTIVE", joined_at: now },
    { space_id: spaceId, subject_did_hash: peerHash, status: "ACTIVE", joined_at: now }
  ]);
  await db("social_space_crews").insert({
    crew_id: crewId,
    space_id: spaceId,
    name: "Pulse Crew",
    created_by_subject_hash: subjectHash,
    created_at: now
  });
  await db("social_space_crew_members").insert([
    { crew_id: crewId, subject_hash: subjectHash, role: "captain", joined_at: now },
    { crew_id: crewId, subject_hash: peerHash, role: "member", joined_at: now }
  ]);
  await db("social_space_presence_pings").insert([
    { space_id: spaceId, subject_hash: subjectHash, last_seen_at: now },
    { space_id: spaceId, subject_hash: peerHash, last_seen_at: now }
  ]);
  await db("sync_sessions").insert({
    session_id: sessionId,
    space_id: spaceId,
    kind: "huddle",
    host_subject_did_hash: subjectHash,
    status: "ACTIVE",
    created_at: now
  });
  await db("social_space_challenges").insert({
    challenge_id: challengeId,
    space_id: spaceId,
    cadence: "daily",
    title: "Soon ending",
    starts_at: now,
    ends_at: new Date(Date.now() + 20 * 60 * 1000).toISOString(),
    created_by_subject_hash: subjectHash,
    status: "ACTIVE",
    created_at: now
  });
  await db("social_space_streaks").insert({
    space_id: spaceId,
    subject_hash: subjectHash,
    streak_type: "daily_challenge",
    current_count: 2,
    best_count: 2,
    last_completed_at: now,
    updated_at: now
  });
  const response = await app.inject({
    method: "GET",
    url: `/v1/social/spaces/${spaceId}/pulse?subjectDid=${encodeURIComponent(subjectDid)}`
  });
  assert.equal(response.statusCode, 200);
  const payload = response.json() as { cards?: Array<{ type?: string }> };
  const types = new Set((payload.cards ?? []).map((entry) => String(entry.type ?? "")));
  assert.equal(types.has("crew_active"), true);
  assert.equal(types.has("hangout_live"), true);
  assert.equal(types.has("challenge_ending"), true);
  assert.equal(types.has("streak_risk"), true);
  assert.equal(JSON.stringify(payload).includes(subjectHash), false);
  await db("social_space_streaks").where({ space_id: spaceId }).del();
  await db("social_space_challenges").where({ challenge_id: challengeId }).del();
  await db("sync_sessions").where({ session_id: sessionId }).del();
  await db("social_space_presence_pings").where({ space_id: spaceId }).del();
  await db("social_space_crew_members").where({ crew_id: crewId }).del();
  await db("social_space_crews").where({ crew_id: crewId }).del();
  await db("social_space_memberships").where({ space_id: spaceId }).del();
  await db("social_spaces").where({ space_id: spaceId }).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("pulse preferences toggles hide categories", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/admin/privacy/status")) {
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
  const subjectDid = "did:hedera:testnet:pulse-pref";
  const pseudo = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  });
  const subjectHash = pseudo.didToHash(subjectDid);
  const spaceId = randomUUID();
  const crewId = randomUUID();
  const sessionId = randomUUID();
  const now = new Date().toISOString();
  await db("social_spaces").insert({
    space_id: spaceId,
    slug: `pulse-pref-${spaceId.slice(0, 8)}`,
    display_name: "Pulse Pref Space",
    description: "pulse pref test",
    created_by_subject_did_hash: subjectHash,
    policy_pack_id: "space.default.v1",
    created_at: now
  });
  await db("social_space_memberships").insert({
    space_id: spaceId,
    subject_did_hash: subjectHash,
    status: "ACTIVE",
    joined_at: now
  });
  await db("social_space_crews").insert({
    crew_id: crewId,
    space_id: spaceId,
    name: "Crew Pref",
    created_by_subject_hash: subjectHash,
    created_at: now
  });
  await db("social_space_crew_members").insert({
    crew_id: crewId,
    subject_hash: subjectHash,
    role: "captain",
    joined_at: now
  });
  await db("social_space_presence_pings").insert({
    space_id: spaceId,
    subject_hash: subjectHash,
    last_seen_at: now
  });
  await db("sync_sessions").insert({
    session_id: sessionId,
    space_id: spaceId,
    kind: "huddle",
    host_subject_did_hash: subjectHash,
    status: "ACTIVE",
    created_at: now
  });
  const updated = await app.inject({
    method: "POST",
    url: `/v1/social/spaces/${spaceId}/pulse/preferences`,
    payload: {
      subjectDid,
      notifyCrews: false,
      notifyHangouts: false,
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-pulse-pref",
      audience: "cuncta.action:presence.ping"
    }
  });
  assert.equal(updated.statusCode, 200);
  const pulse = await app.inject({
    method: "GET",
    url: `/v1/social/spaces/${spaceId}/pulse?subjectDid=${encodeURIComponent(subjectDid)}`
  });
  assert.equal(pulse.statusCode, 200);
  const pulsePayload = pulse.json() as { cards?: Array<{ type?: string }> };
  const types = new Set((pulsePayload.cards ?? []).map((entry) => String(entry.type ?? "")));
  assert.equal(types.has("crew_active"), false);
  assert.equal(types.has("hangout_live"), false);
  const prefs = await app.inject({
    method: "GET",
    url: `/v1/social/spaces/${spaceId}/pulse/preferences?subjectDid=${encodeURIComponent(subjectDid)}`
  });
  assert.equal(prefs.statusCode, 200);
  const prefsPayload = prefs.json() as {
    preferences?: { notifyCrews?: boolean; notifyHangouts?: boolean };
  };
  assert.equal(prefsPayload.preferences?.notifyCrews, false);
  assert.equal(prefsPayload.preferences?.notifyHangouts, false);
  await db("sync_sessions").where({ session_id: sessionId }).del();
  await db("social_space_presence_pings").where({ space_id: spaceId }).del();
  await db("social_space_crew_members").where({ crew_id: crewId }).del();
  await db("social_space_crews").where({ crew_id: crewId }).del();
  await db("social_space_pulse_preferences").where({ space_id: spaceId }).del();
  await db("social_space_memberships").where({ space_id: spaceId }).del();
  await db("social_spaces").where({ space_id: spaceId }).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("pulse returns empty cards for tombstoned subject", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/admin/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: true });
    }
    return makeJsonResponse({}, 404);
  }) as typeof fetch;
  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");
  const db = await getDb();
  const app = buildServer();
  await app.ready();
  const subjectDid = "did:hedera:testnet:pulse-tombstone";
  const subjectHash = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  }).didToHash(subjectDid);
  const spaceId = randomUUID();
  const now = new Date().toISOString();
  await db("social_spaces").insert({
    space_id: spaceId,
    slug: `pulse-tomb-${spaceId.slice(0, 8)}`,
    display_name: "Pulse Tombstone",
    description: "pulse tombstone test",
    created_by_subject_did_hash: subjectHash,
    policy_pack_id: "space.default.v1",
    created_at: now
  });
  await db("social_space_memberships").insert({
    space_id: spaceId,
    subject_did_hash: subjectHash,
    status: "ACTIVE",
    joined_at: now
  });
  const response = await app.inject({
    method: "GET",
    url: `/v1/social/spaces/${spaceId}/pulse?subjectDid=${encodeURIComponent(subjectDid)}`
  });
  assert.equal(response.statusCode, 200);
  const payload = response.json() as { cards?: unknown[] };
  assert.equal((payload.cards ?? []).length, 0);
  await db("social_space_memberships").where({ space_id: spaceId }).del();
  await db("social_spaces").where({ space_id: spaceId }).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("banter restricted denies send but allows read", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/admin/privacy/status")) {
      return makeJsonResponse({ restricted: true, tombstoned: false });
    }
    if (url.includes("/v1/requirements")) {
      return makeJsonResponse({ requirements: [{ vct: "cuncta.social.space.member" }] });
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
  const pseudo = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  });
  const senderDid = "did:hedera:testnet:banter-restricted";
  const senderHash = pseudo.didToHash(senderDid);
  const peerHash = pseudo.didToHash("did:hedera:testnet:banter-peer");
  const spaceId = randomUUID();
  const threadId = randomUUID();
  const now = new Date().toISOString();
  await db("social_spaces").insert({
    space_id: spaceId,
    slug: `banter-r-${spaceId.slice(0, 8)}`,
    display_name: "Banter Restricted",
    description: "banter restricted test",
    created_by_subject_did_hash: senderHash,
    policy_pack_id: "space.default.v1",
    created_at: now
  });
  await db("social_space_memberships").insert({
    space_id: spaceId,
    subject_did_hash: senderHash,
    status: "ACTIVE",
    joined_at: now
  });
  await db("social_space_banter_threads").insert({
    thread_id: threadId,
    space_id: spaceId,
    kind: "space_chat",
    created_at: now,
    updated_at: now
  });
  await db("social_banter_messages").insert({
    message_id: randomUUID(),
    thread_id: threadId,
    author_subject_hash: peerHash,
    body_text: "peer says hi",
    body_hash: "hash",
    visibility: "normal",
    created_at: now
  });
  const restrictedPermissionToken = "perm-ban-restricted-12345";
  await db("social_banter_permissions").insert({
    permission_id: randomUUID(),
    thread_id: threadId,
    subject_hash: senderHash,
    permission_hash: createHash("sha256").update(restrictedPermissionToken).digest("hex"),
    expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
    created_at: now
  });
  const denySend = await app.inject({
    method: "POST",
    url: `/v1/social/banter/threads/${threadId}/send`,
    payload: {
      subjectDid: senderDid,
      bodyText: "should fail when restricted",
      permissionToken: restrictedPermissionToken,
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-banter-send-restricted",
      audience: "cuncta.action:banter.message.send"
    }
  });
  assert.equal(denySend.statusCode, 403);
  const read = await app.inject({
    method: "GET",
    url: `/v1/social/banter/threads/${threadId}/messages`
  });
  assert.equal(read.statusCode, 200);
  const readPayload = read.json() as { messages?: unknown[] };
  assert.equal((readPayload.messages ?? []).length, 1);
  await db("social_banter_permissions").where({ thread_id: threadId }).del();
  await db("social_banter_messages").where({ thread_id: threadId }).del();
  await db("social_space_banter_threads").where({ thread_id: threadId }).del();
  await db("social_space_memberships").where({ space_id: spaceId }).del();
  await db("social_spaces").where({ space_id: spaceId }).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("banter tombstoned denies send and hides authored messages", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/admin/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: true });
    }
    if (url.includes("/v1/requirements")) {
      return makeJsonResponse({ requirements: [{ vct: "cuncta.social.space.member" }] });
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
  const pseudo = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  });
  const senderDid = "did:hedera:testnet:banter-tombstone";
  const senderHash = pseudo.didToHash(senderDid);
  const peerHash = pseudo.didToHash("did:hedera:testnet:banter-peer2");
  const spaceId = randomUUID();
  const threadId = randomUUID();
  const now = new Date().toISOString();
  await db("social_spaces").insert({
    space_id: spaceId,
    slug: `banter-t-${spaceId.slice(0, 8)}`,
    display_name: "Banter Tomb",
    description: "banter tomb test",
    created_by_subject_did_hash: senderHash,
    policy_pack_id: "space.default.v1",
    created_at: now
  });
  await db("social_space_memberships").insert({
    space_id: spaceId,
    subject_did_hash: senderHash,
    status: "ACTIVE",
    joined_at: now
  });
  await db("social_space_banter_threads").insert({
    thread_id: threadId,
    space_id: spaceId,
    kind: "space_chat",
    created_at: now,
    updated_at: now
  });
  const authoredMessageId = randomUUID();
  await db("social_banter_messages").insert([
    {
      message_id: authoredMessageId,
      thread_id: threadId,
      author_subject_hash: senderHash,
      body_text: "my old message",
      body_hash: "hash-a",
      visibility: "normal",
      created_at: now
    },
    {
      message_id: randomUUID(),
      thread_id: threadId,
      author_subject_hash: peerHash,
      body_text: "other message",
      body_hash: "hash-b",
      visibility: "normal",
      created_at: now
    }
  ]);
  const tombPermissionToken = "perm-ban-tomb-12345";
  await db("social_banter_permissions").insert({
    permission_id: randomUUID(),
    thread_id: threadId,
    subject_hash: senderHash,
    permission_hash: createHash("sha256").update(tombPermissionToken).digest("hex"),
    expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
    created_at: now
  });
  const denySend = await app.inject({
    method: "POST",
    url: `/v1/social/banter/threads/${threadId}/send`,
    payload: {
      subjectDid: senderDid,
      bodyText: "should fail when tombstoned",
      permissionToken: tombPermissionToken,
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-banter-send-tomb",
      audience: "cuncta.action:banter.message.send"
    }
  });
  assert.equal(denySend.statusCode, 403);
  const read = await app.inject({
    method: "GET",
    url: `/v1/social/banter/threads/${threadId}/messages`
  });
  assert.equal(read.statusCode, 200);
  const readPayload = read.json() as { messages?: Array<{ message_id?: string }> };
  assert.equal(
    (readPayload.messages ?? []).some((entry) => entry.message_id === authoredMessageId),
    false
  );
  await db("social_banter_permissions").where({ thread_id: threadId }).del();
  await db("social_banter_messages").where({ thread_id: threadId }).del();
  await db("social_space_banter_threads").where({ thread_id: threadId }).del();
  await db("social_space_memberships").where({ space_id: spaceId }).del();
  await db("social_spaces").where({ space_id: spaceId }).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("banter moderator can remove message and non-moderator cannot", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.includes("/v1/admin/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: false });
    }
    if (url.includes("/v1/requirements")) {
      return makeJsonResponse({ requirements: [{ vct: "cuncta.social.space.moderator" }] });
    }
    if (url.includes("/v1/verify")) {
      const bodyString = typeof init?.body === "string" ? init.body : "";
      if (bodyString.includes("nonce-banter-mod-deny")) {
        return makeJsonResponse({ decision: "DENY", reasons: ["policy_failed"] });
      }
      return makeJsonResponse({ decision: "ALLOW" });
    }
    return makeJsonResponse({}, 404);
  }) as typeof fetch;
  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");
  const db = await getDb();
  const app = buildServer();
  await app.ready();
  const pseudo = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  });
  const modDid = "did:hedera:testnet:banter-mod";
  const userDid = "did:hedera:testnet:banter-user";
  const modHash = pseudo.didToHash(modDid);
  const userHash = pseudo.didToHash(userDid);
  const spaceId = randomUUID();
  const threadId = randomUUID();
  const messageId = randomUUID();
  const now = new Date().toISOString();
  await db("social_spaces").insert({
    space_id: spaceId,
    slug: `banter-m-${spaceId.slice(0, 8)}`,
    display_name: "Banter Moderate",
    description: "banter moderate test",
    created_by_subject_did_hash: modHash,
    policy_pack_id: "space.default.v1",
    created_at: now
  });
  await db("social_space_memberships").insert([
    { space_id: spaceId, subject_did_hash: modHash, status: "ACTIVE", joined_at: now },
    { space_id: spaceId, subject_did_hash: userHash, status: "ACTIVE", joined_at: now }
  ]);
  await db("social_space_banter_threads").insert({
    thread_id: threadId,
    space_id: spaceId,
    kind: "space_chat",
    created_at: now,
    updated_at: now
  });
  await db("social_banter_messages").insert({
    message_id: messageId,
    thread_id: threadId,
    author_subject_hash: userHash,
    body_text: "keep it clean",
    body_hash: "hash-mod",
    visibility: "normal",
    created_at: now
  });
  const deny = await app.inject({
    method: "POST",
    url: `/v1/social/banter/messages/${messageId}/moderate`,
    payload: {
      subjectDid: userDid,
      reasonCode: "abuse",
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-banter-mod-deny",
      audience: "cuncta.action:banter.message.moderate"
    }
  });
  assert.equal(deny.statusCode, 403);
  const allow = await app.inject({
    method: "POST",
    url: `/v1/social/banter/messages/${messageId}/moderate`,
    payload: {
      subjectDid: modDid,
      reasonCode: "abuse",
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-banter-mod-allow",
      audience: "cuncta.action:banter.message.moderate"
    }
  });
  assert.equal(allow.statusCode, 200);
  const moderated = await db("social_banter_messages")
    .where({ message_id: messageId })
    .first();
  assert.equal(moderated?.visibility, "removed_by_mod");
  await db("social_banter_messages").where({ message_id: messageId }).del();
  await db("social_space_banter_threads").where({ thread_id: threadId }).del();
  await db("social_space_memberships").where({ space_id: spaceId }).del();
  await db("social_spaces").where({ space_id: spaceId }).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("space status messages respect ttl cleanup", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/admin/privacy/status")) {
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
  const { config } = await import("../config.js");
  const db = await getDb();
  const app = buildServer();
  await app.ready();
  const pseudo = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  });
  const subjectDid = "did:hedera:testnet:status-main";
  const subjectHash = pseudo.didToHash(subjectDid);
  const spaceId = randomUUID();
  const now = new Date().toISOString();
  await db("social_spaces").insert({
    space_id: spaceId,
    slug: `status-${spaceId.slice(0, 8)}`,
    display_name: "Status Space",
    description: "status ttl test",
    created_by_subject_did_hash: subjectHash,
    policy_pack_id: "space.default.v1",
    created_at: now
  });
  await db("social_space_memberships").insert({
    space_id: spaceId,
    subject_did_hash: subjectHash,
    status: "ACTIVE",
    joined_at: now
  });
  const staleTime = new Date(Date.now() - (config.BANTER_STATUS_TTL_SECONDS + 30) * 1000).toISOString();
  await db("social_presence_status_messages").insert({
    status_id: randomUUID(),
    space_id: spaceId,
    crew_id: null,
    subject_hash: pseudo.didToHash("did:hedera:testnet:status-stale"),
    status_text: "stale",
    status_hash: "hash-stale",
    mode: "quiet",
    updated_at: staleTime
  });
  const setStatus = await app.inject({
    method: "POST",
    url: `/v1/social/spaces/${spaceId}/status`,
    payload: {
      subjectDid,
      mode: "active",
      statusText: "grinding challenge",
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-status-set",
      audience: "cuncta.action:banter.status.set"
    }
  });
  assert.equal(setStatus.statusCode, 200);
  const getStatus = await app.inject({
    method: "GET",
    url: `/v1/social/spaces/${spaceId}/status?viewerDid=${encodeURIComponent(subjectDid)}`
  });
  assert.equal(getStatus.statusCode, 200);
  const payload = getStatus.json() as {
    counts?: { quiet?: number; active?: number; immersive?: number };
    you?: { status_text?: string };
  };
  assert.equal(payload.counts?.quiet, 0);
  assert.equal(payload.you?.status_text, "grinding challenge");
  await db("social_presence_status_messages").where({ space_id: spaceId }).del();
  await db("social_space_memberships").where({ space_id: spaceId }).del();
  await db("social_spaces").where({ space_id: spaceId }).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("realtime publish requires broadcast permission", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/admin/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: false });
    }
    if (url.includes("/v1/requirements")) {
      return makeJsonResponse({ requirements: [{ vct: "cuncta.social.space.member" }] });
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
  const pseudo = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  });
  const subjectDid = "did:hedera:testnet:rt-no-broadcast";
  const subjectHash = pseudo.didToHash(subjectDid);
  const spaceId = randomUUID();
  const now = new Date().toISOString();
  await db("social_spaces").insert({
    space_id: spaceId,
    slug: `rt-nb-${spaceId.slice(0, 8)}`,
    display_name: "Realtime NB",
    description: "rt test",
    created_by_subject_did_hash: subjectHash,
    policy_pack_id: "space.default.v1",
    created_at: now
  });
  await db("social_space_memberships").insert({
    space_id: spaceId,
    subject_did_hash: subjectHash,
    status: "ACTIVE",
    joined_at: now
  });
  const tokenRes = await app.inject({
    method: "POST",
    url: "/v1/social/realtime/token",
    payload: {
      subjectDid,
      channel: "presence",
      spaceId,
      canBroadcast: false,
      presentation: "fake.presentation.token",
      nonce: "nonce-rt-token-nb",
      audience: "cuncta.action:presence.ping"
    }
  });
  assert.equal(tokenRes.statusCode, 200);
  const tokenPayload = tokenRes.json() as { permissionToken: string };
  const publishRes = await app.inject({
    method: "POST",
    url: "/v1/social/realtime/publish",
    payload: {
      permissionToken: tokenPayload.permissionToken,
      eventType: "presence.ping",
      payload: { mode: "active" }
    }
  });
  assert.equal(publishRes.statusCode, 403);
  await db("social_realtime_permissions").where({ subject_hash: subjectHash }).del();
  await db("social_realtime_events").where({ space_id: spaceId }).del();
  await db("social_space_memberships").where({ space_id: spaceId }).del();
  await db("social_spaces").where({ space_id: spaceId }).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("realtime publish applies rate limits", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/admin/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: false });
    }
    if (url.includes("/v1/requirements")) {
      return makeJsonResponse({ requirements: [{ vct: "cuncta.social.space.member" }] });
    }
    if (url.includes("/v1/verify")) {
      return makeJsonResponse({ decision: "ALLOW" });
    }
    return makeJsonResponse({}, 404);
  }) as typeof fetch;
  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");
  const { config } = await import("../config.js");
  const db = await getDb();
  const app = buildServer();
  await app.ready();
  const pseudo = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  });
  const subjectDid = "did:hedera:testnet:rt-rate";
  const subjectHash = pseudo.didToHash(subjectDid);
  const spaceId = randomUUID();
  const now = new Date().toISOString();
  await db("social_spaces").insert({
    space_id: spaceId,
    slug: `rt-rate-${spaceId.slice(0, 8)}`,
    display_name: "Realtime Rate",
    description: "rt test",
    created_by_subject_did_hash: subjectHash,
    policy_pack_id: "space.default.v1",
    created_at: now
  });
  await db("social_space_memberships").insert({
    space_id: spaceId,
    subject_did_hash: subjectHash,
    status: "ACTIVE",
    joined_at: now
  });
  const tokenRes = await app.inject({
    method: "POST",
    url: "/v1/social/realtime/token",
    payload: {
      subjectDid,
      channel: "presence",
      spaceId,
      canBroadcast: true,
      presentation: "fake.presentation.token",
      nonce: "nonce-rt-token-rate",
      audience: "cuncta.action:presence.ping"
    }
  });
  assert.equal(tokenRes.statusCode, 200);
  const tokenPayload = tokenRes.json() as { permissionToken: string };
  let sawRateLimit = false;
  for (let index = 0; index < config.REALTIME_PUBLISH_RATE_MAX_PER_WINDOW + 3; index += 1) {
    const publishRes = await app.inject({
      method: "POST",
      url: "/v1/social/realtime/publish",
      payload: {
        permissionToken: tokenPayload.permissionToken,
        eventType: "presence.ping",
        payload: { seq: index }
      }
    });
    if (publishRes.statusCode === 429) {
      sawRateLimit = true;
      break;
    }
  }
  assert.equal(sawRateLimit, true);
  await db("social_realtime_permissions").where({ subject_hash: subjectHash }).del();
  await db("social_realtime_events").where({ space_id: spaceId }).del();
  await db("social_space_memberships").where({ space_id: spaceId }).del();
  await db("social_spaces").where({ space_id: spaceId }).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("realtime events support deterministic cursor pagination with after and limit", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/admin/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: false });
    }
    if (url.includes("/v1/requirements")) {
      return makeJsonResponse({ requirements: [{ vct: "cuncta.social.space.member" }] });
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
  const pseudo = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  });
  const subjectDid = "did:hedera:testnet:rt-cursor";
  const subjectHash = pseudo.didToHash(subjectDid);
  const spaceId = randomUUID();
  const now = new Date().toISOString();
  await db("social_spaces").insert({
    space_id: spaceId,
    slug: `rt-cursor-${spaceId.slice(0, 8)}`,
    display_name: "Realtime Cursor",
    description: "rt cursor test",
    created_by_subject_did_hash: subjectHash,
    policy_pack_id: "space.default.v1",
    created_at: now
  });
  await db("social_space_memberships").insert({
    space_id: spaceId,
    subject_did_hash: subjectHash,
    status: "ACTIVE",
    joined_at: now
  });
  const tokenRes = await app.inject({
    method: "POST",
    url: "/v1/social/realtime/token",
    payload: {
      subjectDid,
      channel: "presence",
      spaceId,
      canBroadcast: true,
      presentation: "fake.presentation.token",
      nonce: "nonce-rt-token-cursor",
      audience: "cuncta.action:presence.ping"
    }
  });
  assert.equal(tokenRes.statusCode, 200);
  const tokenPayload = tokenRes.json() as { permissionToken: string };
  for (let index = 0; index < 3; index += 1) {
    const publishRes = await app.inject({
      method: "POST",
      url: "/v1/social/realtime/publish",
      payload: {
        permissionToken: tokenPayload.permissionToken,
        eventType: "presence.ping",
        payload: { seq: index }
      }
    });
    assert.equal(publishRes.statusCode, 200);
  }
  const page1 = await app.inject({
    method: "GET",
    url: `/v1/social/realtime/events?permissionToken=${encodeURIComponent(tokenPayload.permissionToken)}&limit=2`
  });
  assert.equal(page1.statusCode, 200);
  const payload1 = page1.json() as {
    events: Array<{ cursor?: string | null; payload?: { seq?: number } }>;
    nextCursor?: string | null;
  };
  assert.equal(payload1.events.length, 2);
  const c1 = Number(payload1.events[0]?.cursor ?? "0");
  const c2 = Number(payload1.events[1]?.cursor ?? "0");
  assert.ok(Number.isFinite(c1) && Number.isFinite(c2) && c2 > c1);
  assert.equal(payload1.nextCursor, payload1.events[1]?.cursor ?? null);
  const page2 = await app.inject({
    method: "GET",
    url: `/v1/social/realtime/events?permissionToken=${encodeURIComponent(
      tokenPayload.permissionToken
    )}&after=${encodeURIComponent(String(payload1.nextCursor ?? ""))}&limit=2`
  });
  assert.equal(page2.statusCode, 200);
  const payload2 = page2.json() as { events: Array<{ cursor?: string | null; payload?: { seq?: number } }> };
  assert.equal(payload2.events.length, 1);
  const c3 = Number(payload2.events[0]?.cursor ?? "0");
  assert.ok(Number.isFinite(c3) && c3 > c2);
  const seqs = [...payload1.events, ...payload2.events].map((event) => event.payload?.seq);
  assert.deepEqual(seqs, [0, 1, 2]);
  await db("social_realtime_permissions").where({ subject_hash: subjectHash }).del();
  await db("social_realtime_events").where({ space_id: spaceId }).del();
  await db("social_space_memberships").where({ space_id: spaceId }).del();
  await db("social_spaces").where({ space_id: spaceId }).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("post imageRefs validation denies cross-owner and space-mismatch refs", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/admin/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: false });
    }
    if (url.includes("/v1/requirements")) {
      return makeJsonResponse({ requirements: [{ vct: "cuncta.social.can_post" }] });
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
  const pseudo = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  });
  const ownerDid = "did:hedera:testnet:image-owner";
  const attackerDid = "did:hedera:testnet:image-attacker";
  const ownerHash = pseudo.didToHash(ownerDid);
  const attackerHash = pseudo.didToHash(attackerDid);
  const stolenAssetId = randomUUID();
  const now = new Date().toISOString();
  await db("social_media_assets").insert({
    asset_id: stolenAssetId,
    owner_subject_hash: ownerHash,
    space_id: null,
    media_kind: "image",
    storage_provider: "s3",
    object_key: `original/${stolenAssetId}.jpg`,
    thumbnail_object_key: `thumb/${stolenAssetId}.jpg`,
    mime_type: "image/jpeg",
    byte_size: 2048,
    sha256_hex: createHash("sha256").update("owner-asset").digest("hex"),
    status: "ACTIVE",
    created_at: now,
    finalized_at: now
  });
  const deniedCrossOwner = await app.inject({
    method: "POST",
    url: "/v1/social/post",
    payload: {
      subjectDid: attackerDid,
      content: "cannot steal image",
      imageRefs: [stolenAssetId],
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-image-cross-owner",
      audience: "cuncta.action:social.post.create"
    }
  });
  assert.equal(deniedCrossOwner.statusCode, 400);

  const spaceA = randomUUID();
  const spaceB = randomUUID();
  await db("social_spaces").insert([
    {
      space_id: spaceA,
      slug: `img-space-a-${spaceA.slice(0, 8)}`,
      display_name: "Image Space A",
      description: "test",
      created_by_subject_did_hash: attackerHash,
      policy_pack_id: "space.default.v1",
      created_at: now
    },
    {
      space_id: spaceB,
      slug: `img-space-b-${spaceB.slice(0, 8)}`,
      display_name: "Image Space B",
      description: "test",
      created_by_subject_did_hash: attackerHash,
      policy_pack_id: "space.default.v1",
      created_at: now
    }
  ]);
  await db("social_space_memberships").insert({
    space_id: spaceB,
    subject_did_hash: attackerHash,
    status: "ACTIVE",
    joined_at: now
  });
  const scopedAssetId = randomUUID();
  await db("social_media_assets").insert({
    asset_id: scopedAssetId,
    owner_subject_hash: attackerHash,
    space_id: spaceA,
    media_kind: "image",
    storage_provider: "s3",
    object_key: `original/${scopedAssetId}.jpg`,
    thumbnail_object_key: null,
    mime_type: "image/jpeg",
    byte_size: 2048,
    sha256_hex: createHash("sha256").update("scoped-asset").digest("hex"),
    status: "ACTIVE",
    created_at: now,
    finalized_at: now
  });
  const deniedScopeMismatch = await app.inject({
    method: "POST",
    url: "/v1/social/space/post",
    payload: {
      subjectDid: attackerDid,
      spaceId: spaceB,
      content: "cannot cross-attach",
      imageRefs: [scopedAssetId],
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-image-space-mismatch",
      audience: "cuncta.action:social.space.post.create"
    }
  });
  assert.equal(deniedScopeMismatch.statusCode, 400);

  await db("social_media_assets").whereIn("asset_id", [stolenAssetId, scopedAssetId]).del();
  await db("social_space_memberships").whereIn("space_id", [spaceA, spaceB]).del();
  await db("social_spaces").whereIn("space_id", [spaceA, spaceB]).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("feed redacts image refs for erased media assets", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/admin/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: false });
    }
    return makeJsonResponse({}, 404);
  }) as typeof fetch;
  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");
  const db = await getDb();
  const app = buildServer();
  await app.ready();
  const pseudo = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  });
  const subjectHash = pseudo.didToHash("did:hedera:testnet:feed-redact-author");
  const assetId = randomUUID();
  const postId = randomUUID();
  const now = new Date().toISOString();
  await db("social_media_assets").insert({
    asset_id: assetId,
    owner_subject_hash: subjectHash,
    space_id: null,
    media_kind: "image",
    storage_provider: "s3",
    object_key: `original/${assetId}.jpg`,
    thumbnail_object_key: `thumb/${assetId}.jpg`,
    mime_type: "image/jpeg",
    byte_size: 4096,
    sha256_hex: createHash("sha256").update("feed-redact").digest("hex"),
    status: "ERASED",
    created_at: now,
    finalized_at: now,
    erased_at: now,
    deleted_at: now
  });
  await db("social_posts").insert({
    post_id: postId,
    author_subject_did_hash: subjectHash,
    content_text: "post with erased media",
    content_hash: hashCanonicalJson({ text: "post with erased media" }),
    image_refs: JSON.stringify([assetId]),
    created_at: now
  });
  const response = await app.inject({
    method: "GET",
    url: "/v1/social/feed"
  });
  assert.equal(response.statusCode, 200);
  const payload = response.json() as {
    posts?: Array<{ post_id?: string; image_refs?: string[]; image_refs_redacted_count?: number }>;
  };
  const post = (payload.posts ?? []).find((entry) => entry.post_id === postId);
  assert.ok(post);
  assert.deepEqual(post?.image_refs ?? [], []);
  assert.equal(Number(post?.image_refs_redacted_count ?? 0), 1);
  await db("social_posts").where({ post_id: postId }).del();
  await db("social_media_assets").where({ asset_id: assetId }).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("media view request returns ok for authorized member and unavailable for unauthorized", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/admin/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: false });
    }
    return makeJsonResponse({}, 404);
  }) as typeof fetch;
  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");
  const db = await getDb();
  const app = buildServer();
  await app.ready();
  const pseudo = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  });
  const ownerDid = "did:hedera:testnet:view-owner";
  const memberDid = "did:hedera:testnet:view-member";
  const strangerDid = "did:hedera:testnet:view-stranger";
  const ownerHash = pseudo.didToHash(ownerDid);
  const memberHash = pseudo.didToHash(memberDid);
  const spaceId = randomUUID();
  const spacePostId = randomUUID();
  const assetId = randomUUID();
  const now = new Date().toISOString();
  await db("social_spaces").insert({
    space_id: spaceId,
    slug: `media-view-${spaceId.slice(0, 8)}`,
    display_name: "Media View Space",
    description: "view test",
    created_by_subject_did_hash: ownerHash,
    policy_pack_id: "space.default.v1",
    created_at: now
  });
  await db("social_space_memberships").insert({
    space_id: spaceId,
    subject_did_hash: memberHash,
    status: "ACTIVE",
    joined_at: now
  });
  await db("social_media_assets").insert({
    asset_id: assetId,
    owner_subject_hash: ownerHash,
    space_id: spaceId,
    media_kind: "image",
    storage_provider: "s3",
    object_key: `original/${assetId}.jpg`,
    thumbnail_object_key: `thumb/${assetId}.jpg`,
    mime_type: "image/jpeg",
    byte_size: 4096,
    sha256_hex: createHash("sha256").update("media-view-asset").digest("hex"),
    status: "ACTIVE",
    created_at: now,
    finalized_at: now
  });
  await db("social_space_posts").insert({
    space_post_id: spacePostId,
    space_id: spaceId,
    author_subject_did_hash: ownerHash,
    content_text: "space post with image",
    content_hash: hashCanonicalJson({ text: "space post with image" }),
    image_refs: JSON.stringify([assetId]),
    created_at: now
  });
  const authorized = await app.inject({
    method: "POST",
    url: "/v1/social/media/view/request",
    payload: {
      viewerDid: memberDid,
      items: [
        {
          assetId,
          context: {
            kind: "spacePost",
            spaceId,
            postId: spacePostId
          }
        }
      ]
    }
  });
  assert.equal(authorized.statusCode, 200);
  const okPayload = authorized.json() as {
    results?: Array<{ status?: string; originalUrl?: string; thumbUrl?: string | null }>;
  };
  assert.equal(okPayload.results?.[0]?.status, "ok");
  assert.ok((okPayload.results?.[0]?.originalUrl ?? "").length > 10);
  assert.ok((okPayload.results?.[0]?.thumbUrl ?? "").length > 10);

  const unauthorized = await app.inject({
    method: "POST",
    url: "/v1/social/media/view/request",
    payload: {
      viewerDid: strangerDid,
      items: [
        {
          assetId,
          context: {
            kind: "spacePost",
            spaceId,
            postId: spacePostId
          }
        }
      ]
    }
  });
  assert.equal(unauthorized.statusCode, 200);
  const deniedPayload = unauthorized.json() as { results?: Array<{ status?: string }> };
  assert.equal(deniedPayload.results?.[0]?.status, "unavailable");

  await db("social_space_posts").where({ space_post_id: spacePostId }).del();
  await db("social_media_assets").where({ asset_id: assetId }).del();
  await db("social_space_memberships").where({ space_id: spaceId }).del();
  await db("social_spaces").where({ space_id: spaceId }).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("media view fails closed when viewer privacy lookup times out and returns quickly", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (_input: string | URL, init?: RequestInit) => {
    const signal = init?.signal;
    return await new Promise<Response>((_resolve, reject) => {
      if (signal?.aborted) {
        reject(new Error("privacy_aborted"));
        return;
      }
      signal?.addEventListener(
        "abort",
        () => {
          reject(new Error("privacy_aborted"));
        },
        { once: true }
      );
    });
  }) as typeof fetch;
  const { buildServer } = await import("../server.js");
  const app = buildServer();
  await app.ready();
  const startedAt = Date.now();
  const response = await app.inject({
    method: "POST",
    url: "/v1/social/media/view/request",
    payload: {
      viewerDid: "did:hedera:testnet:viewer-timeout",
      items: [
        {
          assetId: randomUUID(),
          context: {
            kind: "post",
            postId: randomUUID()
          }
        }
      ]
    }
  });
  const elapsedMs = Date.now() - startedAt;
  assert.equal(response.statusCode, 200);
  const payload = response.json() as { results?: Array<{ status?: string }> };
  assert.equal(payload.results?.[0]?.status, "unavailable");
  assert.ok(
    elapsedMs < 2_000,
    `expected bounded timeout response, elapsedMs=${elapsedMs} timeoutMs=${process.env.ISSUER_PRIVACY_STATUS_TIMEOUT_MS}`
  );
  await app.close();
  globalThis.fetch = originalFetch;
});

test("stale pending media uploads are cleaned up opportunistically", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/admin/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: false });
    }
    if (url.includes("/v1/requirements")) {
      return makeJsonResponse({ requirements: [{ vct: "cuncta.social.can_post" }] });
    }
    if (url.includes("/v1/verify")) {
      return makeJsonResponse({ decision: "ALLOW" });
    }
    return makeJsonResponse({}, 404);
  }) as typeof fetch;
  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");
  const { config } = await import("../config.js");
  const { mediaStorageAdapter, __setMediaUploadCleanupLastRunAtForTests } = await import("./social.js");
  const db = await getDb();
  const app = buildServer();
  await app.ready();
  const pseudo = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  });
  const subjectDid = "did:hedera:testnet:stale-cleanup";
  const subjectHash = pseudo.didToHash(subjectDid);
  const staleAssetId = randomUUID();
  const staleObjectKey = `original/${staleAssetId}.jpg`;
  const staleCreatedAt = new Date(
    Date.now() - (config.MEDIA_PRESIGN_TTL_SECONDS + 120) * 1000
  ).toISOString();
  await db("social_media_assets").insert({
    asset_id: staleAssetId,
    owner_subject_hash: subjectHash,
    space_id: null,
    media_kind: "image",
    storage_provider: "s3",
    object_key: staleObjectKey,
    thumbnail_object_key: null,
    mime_type: "image/jpeg",
    byte_size: 2048,
    sha256_hex: createHash("sha256").update("stale-asset").digest("hex"),
    status: "PENDING",
    created_at: staleCreatedAt
  });
  __setMediaUploadCleanupLastRunAtForTests(0);
  const originalDelete = mediaStorageAdapter.deleteMediaObjects;
  const deletedKeys: string[] = [];
  mediaStorageAdapter.deleteMediaObjects = async (keys) => {
    deletedKeys.push(...keys.filter((value): value is string => typeof value === "string"));
  };
  try {
    const response = await app.inject({
      method: "POST",
      url: "/v1/social/media/upload/request",
      payload: {
        subjectDid,
        mimeType: "image/jpeg",
        byteSize: 2048,
        sha256Hex: createHash("sha256").update("fresh-upload").digest("hex"),
        presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
        nonce: "nonce-stale-cleanup-trigger",
        audience: "cuncta.action:social.post.create"
      }
    });
    assert.equal(response.statusCode, 200);
    const staleRow = await db("social_media_assets").where({ asset_id: staleAssetId }).first();
    assert.equal(staleRow?.status, "ERASED");
    assert.ok(staleRow?.erased_at);
    assert.equal(deletedKeys.includes(staleObjectKey), true);
  } finally {
    mediaStorageAdapter.deleteMediaObjects = originalDelete;
  }
  await db("social_media_assets").where({ owner_subject_hash: subjectHash }).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("stale cleanup delete does not block upload request when delete hangs", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/admin/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: false });
    }
    if (url.includes("/v1/requirements")) {
      return makeJsonResponse({ requirements: [{ vct: "cuncta.social.can_post" }] });
    }
    if (url.includes("/v1/verify")) {
      return makeJsonResponse({ decision: "ALLOW" });
    }
    return makeJsonResponse({}, 404);
  }) as typeof fetch;
  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");
  const { config } = await import("../config.js");
  const { mediaStorageAdapter, __setMediaUploadCleanupLastRunAtForTests } = await import("./social.js");
  const db = await getDb();
  const app = buildServer();
  await app.ready();
  const pseudo = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  });
  const subjectDid = "did:hedera:testnet:stale-cleanup-hanging-delete";
  const subjectHash = pseudo.didToHash(subjectDid);
  const staleAssetId = randomUUID();
  const staleCreatedAt = new Date(
    Date.now() - (config.MEDIA_PRESIGN_TTL_SECONDS + 120) * 1000
  ).toISOString();
  await db("social_media_assets").insert({
    asset_id: staleAssetId,
    owner_subject_hash: subjectHash,
    space_id: null,
    media_kind: "image",
    storage_provider: "s3",
    object_key: `original/${staleAssetId}.jpg`,
    thumbnail_object_key: null,
    mime_type: "image/jpeg",
    byte_size: 2048,
    sha256_hex: createHash("sha256").update("stale-asset-hanging").digest("hex"),
    status: "PENDING",
    created_at: staleCreatedAt
  });
  __setMediaUploadCleanupLastRunAtForTests(0);
  const originalDelete = mediaStorageAdapter.deleteMediaObjects;
  mediaStorageAdapter.deleteMediaObjects = async () => new Promise<void>(() => undefined);
  try {
    const outcome = await Promise.race([
      app
        .inject({
          method: "POST",
          url: "/v1/social/media/upload/request",
          payload: {
            subjectDid,
            mimeType: "image/jpeg",
            byteSize: 2048,
            sha256Hex: createHash("sha256").update("fresh-upload-hanging").digest("hex"),
            presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
            nonce: "nonce-stale-cleanup-non-blocking",
            audience: "cuncta.action:social.post.create"
          }
        })
        .then((response) => ({ kind: "response" as const, response })),
      new Promise<{ kind: "timeout" }>((resolve) => {
        setTimeout(() => resolve({ kind: "timeout" }), 1500);
      })
    ]);
    if (outcome.kind !== "response") {
      assert.fail("upload request blocked on stale cleanup delete");
    }
    assert.equal(outcome.response.statusCode, 200);
    const staleRow = await db("social_media_assets").where({ asset_id: staleAssetId }).first();
    assert.equal(staleRow?.status, "ERASED");
  } finally {
    mediaStorageAdapter.deleteMediaObjects = originalDelete;
  }
  await db("social_media_assets").where({ owner_subject_hash: subjectHash }).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("stale cleanup delete rejection is swallowed and does not create unhandled rejection", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/admin/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: false });
    }
    if (url.includes("/v1/requirements")) {
      return makeJsonResponse({ requirements: [{ vct: "cuncta.social.can_post" }] });
    }
    if (url.includes("/v1/verify")) {
      return makeJsonResponse({ decision: "ALLOW" });
    }
    return makeJsonResponse({}, 404);
  }) as typeof fetch;
  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");
  const { config } = await import("../config.js");
  const { mediaStorageAdapter, __setMediaUploadCleanupLastRunAtForTests } = await import("./social.js");
  const db = await getDb();
  const app = buildServer();
  await app.ready();
  const pseudo = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  });
  const subjectDid = "did:hedera:testnet:stale-cleanup-rejected-delete";
  const subjectHash = pseudo.didToHash(subjectDid);
  const staleAssetId = randomUUID();
  const staleCreatedAt = new Date(
    Date.now() - (config.MEDIA_PRESIGN_TTL_SECONDS + 120) * 1000
  ).toISOString();
  await db("social_media_assets").insert({
    asset_id: staleAssetId,
    owner_subject_hash: subjectHash,
    space_id: null,
    media_kind: "image",
    storage_provider: "s3",
    object_key: `original/${staleAssetId}.jpg`,
    thumbnail_object_key: null,
    mime_type: "image/jpeg",
    byte_size: 2048,
    sha256_hex: createHash("sha256").update("stale-asset-rejected").digest("hex"),
    status: "PENDING",
    created_at: staleCreatedAt
  });
  __setMediaUploadCleanupLastRunAtForTests(0);
  const originalDelete = mediaStorageAdapter.deleteMediaObjects;
  mediaStorageAdapter.deleteMediaObjects = async () => {
    throw new Error("delete_failed_for_test");
  };
  const unhandled: unknown[] = [];
  const onUnhandled = (reason: unknown) => {
    unhandled.push(reason);
  };
  process.on("unhandledRejection", onUnhandled);
  try {
    const response = await app.inject({
      method: "POST",
      url: "/v1/social/media/upload/request",
      payload: {
        subjectDid,
        mimeType: "image/jpeg",
        byteSize: 2048,
        sha256Hex: createHash("sha256").update("fresh-upload-rejected").digest("hex"),
        presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
        nonce: "nonce-stale-cleanup-rejected",
        audience: "cuncta.action:social.post.create"
      }
    });
    assert.equal(response.statusCode, 200);
    let staleRow:
      | {
          status?: string;
          purge_pending?: boolean;
          purge_attempt_count?: number;
        }
      | undefined;
    for (let attempt = 0; attempt < 40; attempt += 1) {
      staleRow = await db("social_media_assets").where({ asset_id: staleAssetId }).first();
      if (staleRow?.purge_pending) break;
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    assert.equal(staleRow?.status, "ERASED");
    assert.equal(staleRow?.purge_pending, true);
    assert.ok(Number(staleRow?.purge_attempt_count ?? 0) >= 1);
    assert.equal(unhandled.length, 0);
  } finally {
    process.off("unhandledRejection", onUnhandled);
    mediaStorageAdapter.deleteMediaObjects = originalDelete;
  }
  await db("social_media_assets").where({ owner_subject_hash: subjectHash }).del();
  await app.close();
  globalThis.fetch = originalFetch;
});

test("purge_pending media retry clears on later opportunistic cleanup", async () => {
  const { getDb } = await import("../db.js");
  const { mediaStorageAdapter, maybeCleanupStaleUploads, __setMediaUploadCleanupLastRunAtForTests } =
    await import("./social.js");
  const db = await getDb();
  const pseudo = createHmacSha256Pseudonymizer({
    pepper: process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456"
  });
  const subjectDid = "did:hedera:testnet:purge-pending-retry";
  const subjectHash = pseudo.didToHash(subjectDid);
  const assetId = randomUUID();
  const nowIso = new Date().toISOString();
  await db("social_media_assets").insert({
    asset_id: assetId,
    owner_subject_hash: subjectHash,
    space_id: null,
    media_kind: "image",
    storage_provider: "s3",
    object_key: `original/${assetId}.jpg`,
    thumbnail_object_key: null,
    mime_type: "image/jpeg",
    byte_size: 2048,
    sha256_hex: createHash("sha256").update("retry-asset").digest("hex"),
    status: "ERASED",
    created_at: nowIso,
    erased_at: nowIso,
    deleted_at: nowIso,
    purge_pending: true,
    purge_attempt_count: 1,
    last_purge_attempt_at: nowIso
  });
  const originalDelete = mediaStorageAdapter.deleteMediaObjects;
  let attempts = 0;
  mediaStorageAdapter.deleteMediaObjects = async () => {
    attempts += 1;
    if (attempts === 1) {
      throw new Error("retry_delete_first_attempt_fails");
    }
  };
  __setMediaUploadCleanupLastRunAtForTests(0);
  try {
    await maybeCleanupStaleUploads({ force: true });
    let afterFirst:
      | {
          purge_pending?: boolean;
          purge_attempt_count?: number;
        }
      | undefined;
    for (let attempt = 0; attempt < 40; attempt += 1) {
      afterFirst = await db("social_media_assets").where({ asset_id: assetId }).first();
      if (Number(afterFirst?.purge_attempt_count ?? 0) >= 2) break;
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    assert.equal(afterFirst?.purge_pending, true);
    assert.ok(Number(afterFirst?.purge_attempt_count ?? 0) >= 2);

    await maybeCleanupStaleUploads({ force: true, nowMs: Date.now() + 1 });
    let afterSecond:
      | {
          purge_pending?: boolean;
          purge_attempt_count?: number;
        }
      | undefined;
    for (let attempt = 0; attempt < 40; attempt += 1) {
      afterSecond = await db("social_media_assets").where({ asset_id: assetId }).first();
      if (afterSecond?.purge_pending === false && Number(afterSecond?.purge_attempt_count ?? 0) >= 3) break;
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    assert.equal(afterSecond?.purge_pending, false);
    assert.ok(Number(afterSecond?.purge_attempt_count ?? 0) >= 3);
  } finally {
    mediaStorageAdapter.deleteMediaObjects = originalDelete;
  }
  await db("social_media_assets").where({ asset_id: assetId }).del();
});
