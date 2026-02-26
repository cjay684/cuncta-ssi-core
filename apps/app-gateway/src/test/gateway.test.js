import assert from "node:assert/strict";

const setupEnv = () => {
  process.env.NODE_ENV = "development";
  process.env.HEDERA_NETWORK = "testnet";
  process.env.DID_SERVICE_BASE_URL = "http://localhost:3001";
  process.env.ISSUER_SERVICE_BASE_URL = "http://localhost:3002";
  process.env.VERIFIER_SERVICE_BASE_URL = "http://localhost:3003";
  process.env.DATABASE_URL =
    process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";
  process.env.SERVICE_JWT_SECRET = "test-secret-12345678901234567890123456789012";
  process.env.SERVICE_JWT_SECRET_SOCIAL = "test-secret-12345678901234567890123456789012-social";
  process.env.SERVICE_JWT_SECRET_DID = "test-secret-12345678901234567890123456789012-did";
  process.env.SERVICE_JWT_SECRET_ISSUER = "test-secret-12345678901234567890123456789012-issuer";
  process.env.SERVICE_JWT_SECRET_VERIFIER = "test-secret-12345678901234567890123456789012-verifier";
  process.env.ALLOW_LEGACY_SERVICE_JWT_SECRET = "false";
  process.env.SERVICE_JWT_AUDIENCE = "cuncta-internal";
  process.env.PSEUDONYMIZER_PEPPER = "pepper-test-123456";
  process.env.USER_PAYS_HANDOFF_SECRET = "user-pays-handoff-secret-12345678901234567890";
};

const run = async (name, fn) => {
  try {
    await fn();
    console.log(`ok - ${name}`);
  } catch (error) {
    console.error(`not ok - ${name}`);
    console.error(error instanceof Error ? (error.stack ?? error.message) : error);
    process.exitCode = 1;
  }
};

await run("sponsored DID create request returns 410 Gone", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const app = buildServer({
    configOverride: { ...config, GATEWAY_ALLOWED_VCTS: ["cuncta.marketplace.seller_good_standing"] }
  });
  const response = await app.inject({
    method: "POST",
    url: "/v1/onboard/did/create/request",
    headers: { "x-device-id": "device-test-1" },
    payload: { network: "testnet", publicKeyMultibase: "z6Mkf5rGMoatqSjLf5fH2h6F4i2kUXqF2z7ABC", options: {} }
  });
  assert.equal(response.statusCode, 410);
  const body = response.json();
  assert.equal(body.error, "sponsored_onboarding_not_supported");
  await app.close();
});

await run("sponsored DID create submit returns 410 Gone", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const app = buildServer({
    configOverride: { ...config, GATEWAY_ALLOWED_VCTS: ["cuncta.marketplace.seller_good_standing"] }
  });
  const response = await app.inject({
    method: "POST",
    url: "/v1/onboard/did/create/submit",
    headers: { "x-device-id": "device-test-2" },
    payload: { state: "11111111-1111-1111-1111-111111111111", signatureB64u: "abc" }
  });
  assert.equal(response.statusCode, 410);
  const body = response.json();
  assert.equal(body.error, "sponsored_onboarding_not_supported");
  await app.close();
});

await run("sponsored onboard issue returns 410 Gone", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const app = buildServer({
    configOverride: { ...config, GATEWAY_ALLOWED_VCTS: ["cuncta.marketplace.seller_good_standing"] }
  });
  const response = await app.inject({
    method: "POST",
    url: "/v1/onboard/issue",
    headers: { "x-device-id": "device-test-3" },
    payload: { subjectDid: "did:hedera:testnet:0.0.1", vct: "cuncta.marketplace.seller_good_standing", claims: {} }
  });
  assert.equal(response.statusCode, 410);
  const body = response.json();
  assert.equal(body.error, "sponsored_onboarding_not_supported");
  await app.close();
});

await run("verify proxy normalizes reasons by default", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const fetchImpl = async () =>
    new Response(JSON.stringify({ decision: "DENY", reasons: ["kb_jwt_missing"] }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  const app = buildServer({
    configOverride: { ...config, GATEWAY_VERIFY_DEBUG_REASONS: false },
    fetchImpl
  });
  const response = await app.inject({
    method: "POST",
    url: "/v1/verify?action=marketplace.list_item",
    payload: { presentation: "x~y", nonce: "nonce-value-123", audience: "audience-value-123" }
  });
  assert.equal(response.statusCode, 200);
  const body = response.json();
  assert.equal(body.decision, "DENY");
  assert.ok(body.message);
  assert.equal(body.reasons, undefined);
  await app.close();
});

await run("verify proxy includes reasons only when enabled", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const fetchImpl = async () =>
    new Response(JSON.stringify({ decision: "DENY", reasons: ["kb_jwt_missing"] }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  const app = buildServer({
    configOverride: { ...config, GATEWAY_VERIFY_DEBUG_REASONS: true },
    fetchImpl
  });
  const response = await app.inject({
    method: "POST",
    url: "/v1/verify?action=marketplace.list_item",
    payload: { presentation: "x~y", nonce: "nonce-value-123", audience: "audience-value-123" }
  });
  assert.equal(response.statusCode, 200);
  const body = response.json();
  assert.equal(body.decision, "DENY");
  assert.ok(Array.isArray(body.reasons));
  assert.ok(body.reasons?.includes("kb_jwt_missing"));
  await app.close();
});

await run("verify proxy debug reasons disabled in production", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  assert.throws(() => {
    buildServer({
      configOverride: { ...config, NODE_ENV: "production", GATEWAY_VERIFY_DEBUG_REASONS: true }
    });
  }, /gateway_verify_debug_reasons_disabled/);
});

await run("parses realtime token from websocket subprotocol safely", async () => {
  setupEnv();
  const { parseWebsocketProtocolHeader, extractRealtimeToken } = await import("../routes/social.ts");
  const token = "abc123-test-token";
  const protocols = parseWebsocketProtocolHeader(`cuncta-rt, cuncta-rt.token.${token}`);
  const resolved = extractRealtimeToken({
    protocols,
    queryToken: null,
    allowQueryToken: true
  });
  assert.equal(resolved.ok, true);
  if (!resolved.ok) {
    throw new Error("expected token extraction success");
  }
  assert.equal(resolved.permissionToken, token);
  assert.equal(resolved.tokenSource, "subprotocol");
  const deniedQuery = extractRealtimeToken({
    protocols: [],
    queryToken: "query-token",
    allowQueryToken: false
  });
  assert.equal(deniedQuery.ok, false);
  assert.equal(deniedQuery.tokenSource, "query");
});

await run("realtime events proxy forwards cursor query params", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  let requestedUrl = "";
  const fetchImpl = async (input) => {
    requestedUrl = String(input);
    return new Response(
      JSON.stringify({
        events: [{ eventId: "evt_1", cursor: "12", eventType: "presence.ping", payload: {}, createdAt: "now" }],
        nextCursor: "12"
      }),
      { status: 200, headers: { "content-type": "application/json" } }
    );
  };
  const app = buildServer({
    configOverride: {
      ...config,
      SOCIAL_SERVICE_BASE_URL: "http://localhost:3005"
    },
    fetchImpl
  });
  const response = await app.inject({
    method: "GET",
    url: "/v1/realtime/events?permissionToken=tok&after=11&limit=1"
  });
  assert.equal(response.statusCode, 200);
  assert.ok(requestedUrl.includes("/v1/social/realtime/events?permissionToken=tok&after=11&limit=1"));
  const body = response.json();
  assert.equal(body.events?.[0]?.cursor, "12");
  assert.equal(body.nextCursor, "12");
  await app.close();
});

await run("realtime events proxy times out without hanging", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const fetchImpl = async (_input, init) => {
    return await new Promise((_resolve, reject) => {
      const signal = init?.signal;
      const fallback = setTimeout(() => {
        reject(new Error("test_timeout_fallback"));
      }, 1500);
      if (signal?.aborted) {
        clearTimeout(fallback);
        reject(new Error("aborted"));
        return;
      }
      signal?.addEventListener(
        "abort",
        () => {
          clearTimeout(fallback);
          reject(new Error("aborted"));
        },
        { once: true }
      );
    });
  };
  const app = buildServer({
    configOverride: {
      ...config,
      SOCIAL_SERVICE_BASE_URL: "http://localhost:3005",
      REALTIME_SOCIAL_FETCH_TIMEOUT_MS: 150
    },
    fetchImpl,
  });
  const startedAt = Date.now();
  const response = await app.inject({
    method: "GET",
    url: "/v1/realtime/events?permissionToken=tok"
  });
  const elapsedMs = Date.now() - startedAt;
  assert.equal(response.statusCode, 503);
  assert.ok(elapsedMs < 2000, `expected bounded timeout; elapsedMs=${elapsedMs}`);
  await app.close();
});

await run("media upload and realtime token include null feeQuote with empty schedule", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const fetchImpl = async (input) => {
    const url = String(input);
    if (url.includes("/v1/social/media/upload/request")) {
      return new Response(JSON.stringify({ uploadId: "upl_1", ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }
    if (url.includes("/v1/social/realtime/token")) {
      return new Response(JSON.stringify({ token: "rt_token", expiresAt: "2026-01-01T00:00:00.000Z" }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }
    return new Response(JSON.stringify({ error: "unexpected_url" }), {
      status: 500,
      headers: { "content-type": "application/json" }
    });
  };
  const app = buildServer({
    configOverride: { ...config, SOCIAL_SERVICE_BASE_URL: "http://localhost:3005" },
    fetchImpl,
  });
  const mediaResponse = await app.inject({
    method: "POST",
    url: "/v1/media/upload/request",
    payload: { fileName: "demo.png" }
  });
  const tokenResponse = await app.inject({
    method: "POST",
    url: "/v1/realtime/token",
    payload: { subjectDid: "did:example:abc" }
  });
  assert.equal(mediaResponse.statusCode, 200);
  assert.equal(tokenResponse.statusCode, 200);
  const mediaBody = mediaResponse.json();
  const tokenBody = tokenResponse.json();
  assert.equal(mediaBody.uploadId, "upl_1");
  assert.equal(tokenBody.token, "rt_token");
  assert.equal(mediaBody.feeQuote, null);
  assert.equal(tokenBody.feeQuote, null);
  assert.equal(mediaBody.paymentRequest, null);
  assert.equal(tokenBody.paymentRequest, null);
  assert.ok(typeof mediaBody.feeScheduleFingerprint === "string");
  assert.ok(typeof tokenBody.feeScheduleFingerprint === "string");
  await app.close();
});

await run("media upload and realtime token include deterministic purpose feeQuote when configured", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const schedule = {
    version: 1,
    assets: {
      HBAR: { kind: "HBAR", symbol: "HBAR", decimals: 8 },
      CUNCTA: {
        kind: "HTS",
        tokenId_testnet: "0.0.12345",
        tokenId_mainnet: "0.0.99999",
        symbol: "CUNCTA",
        decimals: 6
      }
    },
    fees: {
      "purpose:media.upload.request": [
        { asset: "HBAR", amount: "0.02", purpose: "media.upload" },
        { asset: "CUNCTA", amount: "1", purpose: "media.upload" }
      ],
      "purpose:realtime.token": [{ asset: "HBAR", amount: "0.01", purpose: "realtime.publish" }]
    }
  };
  const fetchImpl = async (input) => {
    const url = String(input);
    if (url.includes("/v1/social/media/upload/request")) {
      return new Response(JSON.stringify({ uploadId: "upl_2", ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }
    if (url.includes("/v1/social/realtime/token")) {
      return new Response(JSON.stringify({ token: "rt_token_2", expiresAt: "2026-01-01T00:00:00.000Z" }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }
    return new Response(JSON.stringify({ error: "unexpected_url" }), {
      status: 500,
      headers: { "content-type": "application/json" }
    });
  };
  const app = buildServer({
    configOverride: {
      ...config,
      SOCIAL_SERVICE_BASE_URL: "http://localhost:3005",
      PAYMENTS_RECEIVER_ACCOUNT_ID_TESTNET: "0.0.777777",
      COMMAND_FEE_SCHEDULE_JSON: JSON.stringify(schedule)
    },
    fetchImpl,
  });
  const mediaFirst = await app.inject({
    method: "POST",
    url: "/v1/media/upload/request",
    payload: { fileName: "demo.png" }
  });
  const mediaSecond = await app.inject({
    method: "POST",
    url: "/v1/media/upload/request",
    payload: { fileName: "demo.png" }
  });
  const tokenFirst = await app.inject({
    method: "POST",
    url: "/v1/realtime/token",
    payload: { subjectDid: "did:example:abc" }
  });
  const tokenSecond = await app.inject({
    method: "POST",
    url: "/v1/realtime/token",
    payload: { subjectDid: "did:example:abc" }
  });
  const mediaBodyA = mediaFirst.json();
  const mediaBodyB = mediaSecond.json();
  const tokenBodyA = tokenFirst.json();
  const tokenBodyB = tokenSecond.json();
  assert.equal(mediaFirst.statusCode, 200);
  assert.equal(tokenFirst.statusCode, 200);
  assert.deepEqual(mediaBodyA.feeQuote, mediaBodyB.feeQuote);
  assert.equal(mediaBodyA.feeQuoteFingerprint, mediaBodyB.feeQuoteFingerprint);
  assert.deepEqual(tokenBodyA.feeQuote, tokenBodyB.feeQuote);
  assert.equal(tokenBodyA.feeQuoteFingerprint, tokenBodyB.feeQuoteFingerprint);
  assert.ok(mediaBodyA.feeQuote);
  assert.ok(tokenBodyA.feeQuote);
  assert.ok(mediaBodyA.paymentRequest);
  assert.ok(tokenBodyA.paymentRequest);
  assert.equal(mediaBodyA.paymentRequest.instructions[0].to.accountId, "0.0.777777");
  assert.ok(
    Buffer.byteLength(mediaBodyA.paymentRequest.instructions[0].memo, "utf8") <=
      config.HEDERA_TX_MEMO_MAX_BYTES
  );
  assert.equal(mediaBodyA.paymentRequestFingerprint, mediaBodyB.paymentRequestFingerprint);
  assert.equal(tokenBodyA.paymentRequestFingerprint, tokenBodyB.paymentRequestFingerprint);
  assert.equal(mediaBodyA.uploadId, "upl_2");
  assert.equal(tokenBodyA.token, "rt_token_2");
  await app.close();
});

await run("payment request includes HTS token instruction deterministically", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const schedule = {
    version: 1,
    assets: {
      CUNCTA: {
        kind: "HTS",
        tokenId_testnet: "0.0.12345",
        tokenId_mainnet: "0.0.99999",
        symbol: "CUNCTA",
        decimals: 6
      }
    },
    fees: {
      "purpose:realtime.token": [{ asset: "CUNCTA", amount: "2", purpose: "realtime.publish" }]
    }
  };
  const app = buildServer({
    configOverride: {
      ...config,
      SOCIAL_SERVICE_BASE_URL: "http://localhost:3005",
      PAYMENTS_RECEIVER_ACCOUNT_ID_TESTNET: "0.0.888888",
      COMMAND_FEE_SCHEDULE_JSON: JSON.stringify(schedule)
    },
    fetchImpl: async () =>
      new Response(JSON.stringify({ token: "rt_token_hts", expiresAt: "2026-01-01T00:00:00.000Z" }), {
        status: 200,
        headers: { "content-type": "application/json" }
      }),
  });
  const first = await app.inject({
    method: "POST",
    url: "/v1/realtime/token",
    payload: { subjectDid: "did:example:abc" }
  });
  const second = await app.inject({
    method: "POST",
    url: "/v1/realtime/token",
    payload: { subjectDid: "did:example:abc" }
  });
  const bodyA = first.json();
  const bodyB = second.json();
  assert.equal(first.statusCode, 200);
  assert.equal(bodyA.paymentRequest.instructions.length, 1);
  assert.equal(bodyA.paymentRequest.instructions[0].asset.kind, "HTS");
  assert.equal(bodyA.paymentRequest.instructions[0].asset.tokenId, "0.0.12345");
  assert.equal(bodyA.paymentRequestFingerprint, bodyB.paymentRequestFingerprint);
  await app.close();
});

await run("payment request fingerprint changes when schedule fingerprint changes", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const base = {
    version: 1,
    assets: { HBAR: { kind: "HBAR", symbol: "HBAR", decimals: 8 } }
  };
  const scheduleA = {
    ...base,
    fees: {
      "purpose:realtime.token": [{ asset: "HBAR", amount: "0.01", purpose: "realtime.publish" }]
    }
  };
  const scheduleB = {
    ...base,
    fees: {
      "purpose:realtime.token": [{ asset: "HBAR", amount: "0.02", purpose: "realtime.publish" }]
    }
  };
  const appA = buildServer({
    configOverride: {
      ...config,
      SOCIAL_SERVICE_BASE_URL: "http://localhost:3005",
      PAYMENTS_RECEIVER_ACCOUNT_ID_TESTNET: "0.0.900001",
      COMMAND_FEE_SCHEDULE_JSON: JSON.stringify(scheduleA)
    },
    fetchImpl: async () =>
      new Response(JSON.stringify({ token: "rt_token_a", expiresAt: "2026-01-01T00:00:00.000Z" }), {
        status: 200,
        headers: { "content-type": "application/json" }
      }),
  });
  const appB = buildServer({
    configOverride: {
      ...config,
      SOCIAL_SERVICE_BASE_URL: "http://localhost:3005",
      PAYMENTS_RECEIVER_ACCOUNT_ID_TESTNET: "0.0.900001",
      COMMAND_FEE_SCHEDULE_JSON: JSON.stringify(scheduleB)
    },
    fetchImpl: async () =>
      new Response(JSON.stringify({ token: "rt_token_b", expiresAt: "2026-01-01T00:00:00.000Z" }), {
        status: 200,
        headers: { "content-type": "application/json" }
      }),
  });
  const resA = await appA.inject({
    method: "POST",
    url: "/v1/realtime/token",
    payload: { subjectDid: "did:example:abc" }
  });
  const resB = await appB.inject({
    method: "POST",
    url: "/v1/realtime/token",
    payload: { subjectDid: "did:example:abc" }
  });
  const bodyA = resA.json();
  const bodyB = resB.json();
  assert.notEqual(bodyA.feeScheduleFingerprint, bodyB.feeScheduleFingerprint);
  assert.notEqual(bodyA.paymentRequest.paymentRef, bodyB.paymentRequest.paymentRef);
  assert.notEqual(bodyA.paymentRequestFingerprint, bodyB.paymentRequestFingerprint);
  await appA.close();
  await appB.close();
});

await run("invalid schedule warning omits raw schedule JSON", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const sentinel = "SECRET_SCHEDULE_SENTINEL_DO_NOT_LOG";
  const originalWarn = console.warn;
  const warnings = [];
  console.warn = (...args) => {
    warnings.push(args.map((entry) => String(entry)).join(" "));
  };
  try {
    const app = buildServer({
      configOverride: {
        ...config,
        SOCIAL_SERVICE_BASE_URL: "http://localhost:3005",
        COMMAND_FEE_SCHEDULE_JSON: `{${sentinel}}`
      },
      fetchImpl: async () =>
        new Response(JSON.stringify({ token: "rt_token_3" }), {
          status: 200,
          headers: { "content-type": "application/json" }
        }),
    });
    const response = await app.inject({
      method: "POST",
      url: "/v1/realtime/token",
      payload: { subjectDid: "did:example:abc" }
    });
    assert.equal(response.statusCode, 200);
    const body = response.json();
    assert.equal(body.feeQuote, null);
    assert.equal(body.feeQuoteFingerprint, null);
    assert.equal(body.paymentRequest, null);
    assert.equal(body.paymentRequestFingerprint, null);
    const joinedWarnings = warnings.join("\n");
    assert.ok(joinedWarnings.includes("command.fee.schedule_invalid"));
    assert.ok(!joinedWarnings.includes(sentinel));
    await app.close();
  } finally {
    console.warn = originalWarn;
  }
});

const stripComputedAt = (value) => {
  const clone = JSON.parse(JSON.stringify(value));
  if (clone && typeof clone === "object") {
    delete clone.computedAt;
  }
  return clone;
};

await run("command plan is deterministic for same input and context", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const fetchImpl = async (input) => {
    const url = String(input);
    if (url.includes("/v1/requirements")) {
      return new Response(
        JSON.stringify({
          version: 7,
          policyHash: "policy_hash_abc",
          requirements: [
            { vct: "cuncta.social.space.member", label: "Space member capability" },
            { vct: "cuncta.sync.session_participant", label: "Sync session participant capability" }
          ]
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    }
    if (url.includes("/v1/verify")) {
      return new Response(JSON.stringify({ decision: "ALLOW", reasons: [] }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }
    return new Response(JSON.stringify({ error: "unexpected_url" }), {
      status: 500,
      headers: { "content-type": "application/json" }
    });
  };
  const app = buildServer({
    configOverride: {
      ...config,
      POLICY_SERVICE_BASE_URL: "http://localhost:3101",
      VERIFIER_SERVICE_BASE_URL: "http://localhost:3102"
    },
    fetchImpl,
    writeCommandCenterAuditEvent: async () => {},
  });
  const payload = {
    intent: "join hangout",
    spaceId: "11111111-1111-1111-1111-111111111111",
    subjectDid: "did:example:alice",
    proof: {
      presentation: "proof-presentation",
      nonce: "proof-nonce",
      audience: "proof-audience"
    }
  };
  const first = await app.inject({ method: "POST", url: "/v1/command/plan", payload });
  const second = await app.inject({ method: "POST", url: "/v1/command/plan", payload });
  assert.equal(first.statusCode, 200);
  assert.equal(second.statusCode, 200);
  const firstBody = first.json();
  const secondBody = second.json();
  assert.deepEqual(stripComputedAt(firstBody), stripComputedAt(secondBody));
  assert.equal(firstBody.plannerVersion, "1.1");
  assert.equal(firstBody.feeQuote, null);
  assert.equal(firstBody.feeQuoteFingerprint, null);
  assert.ok(typeof firstBody.feeScheduleFingerprint === "string");
  assert.ok(typeof firstBody.paymentsConfigFingerprint === "string");
  assert.equal(firstBody.paymentsConfigFingerprint, secondBody.paymentsConfigFingerprint);
  assert.equal(firstBody.planDeterminismKey, secondBody.planDeterminismKey);
  await app.close();
});

await run("command plan returns fee quote metadata deterministically when schedule is configured", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const schedule = {
    version: 1,
    assets: {
      HBAR: { kind: "HBAR", symbol: "HBAR", decimals: 8 },
      CUNCTA: {
        kind: "HTS",
        tokenId_testnet: "0.0.12345",
        tokenId_mainnet: "0.0.99999",
        symbol: "CUNCTA",
        decimals: 6
      }
    },
    fees: {
      "action:sync.hangout.join_session": [
        { asset: "CUNCTA", amount: "1", purpose: "intent.plan" },
        { asset: "HBAR", amount: "0.05", purpose: "action.exec" }
      ]
    }
  };
  const fetchImpl = async (input) => {
    const url = String(input);
    if (url.includes("/v1/requirements")) {
      return new Response(JSON.stringify({ version: 1, requirements: [] }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }
    return new Response(JSON.stringify({ decision: "DENY", reasons: ["proof_missing"] }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };
  const app = buildServer({
    configOverride: {
      ...config,
      POLICY_SERVICE_BASE_URL: "http://localhost:3101",
      COMMAND_FEE_SCHEDULE_JSON: JSON.stringify(schedule)
    },
    fetchImpl,
    writeCommandCenterAuditEvent: async () => {},
  });
  const first = await app.inject({
    method: "POST",
    url: "/v1/command/plan",
    payload: { intent: "join hangout", subjectDid: "did:example:fee" }
  });
  const second = await app.inject({
    method: "POST",
    url: "/v1/command/plan",
    payload: { intent: "join hangout", subjectDid: "did:example:fee" }
  });
  assert.equal(first.statusCode, 200);
  assert.equal(second.statusCode, 200);
  const firstBody = first.json();
  const secondBody = second.json();
  assert.deepEqual(firstBody.feeQuote, secondBody.feeQuote);
  assert.equal(firstBody.feeQuoteFingerprint, secondBody.feeQuoteFingerprint);
  assert.ok(firstBody.feeQuote);
  assert.deepEqual(
    firstBody.feeQuote.items.map((entry) => `${entry.asset.kind}:${entry.asset.tokenId ?? ""}:${entry.purpose}`),
    ["HBAR::action.exec", "HTS:0.0.12345:intent.plan"]
  );
  await app.close();
});

await run("command plan determinism key changes when fee schedule changes", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const fetchImpl = async (input) => {
    const url = String(input);
    if (url.includes("/v1/requirements")) {
      return new Response(JSON.stringify({ version: 1, requirements: [] }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }
    return new Response(JSON.stringify({ decision: "DENY", reasons: ["proof_missing"] }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };
  const scheduleA = {
    version: 1,
    assets: { HBAR: { kind: "HBAR", symbol: "HBAR", decimals: 8 } },
    fees: {
      "action:sync.hangout.join_session": [{ asset: "HBAR", amount: "0.05", purpose: "action.exec" }]
    }
  };
  const scheduleB = {
    version: 1,
    assets: { HBAR: { kind: "HBAR", symbol: "HBAR", decimals: 8 } },
    fees: {
      "action:sync.hangout.join_session": [{ asset: "HBAR", amount: "0.08", purpose: "action.exec" }]
    }
  };
  const appA = buildServer({
    configOverride: {
      ...config,
      POLICY_SERVICE_BASE_URL: "http://localhost:3101",
      COMMAND_FEE_SCHEDULE_JSON: JSON.stringify(scheduleA)
    },
    fetchImpl,
    writeCommandCenterAuditEvent: async () => {},
  });
  const appB = buildServer({
    configOverride: {
      ...config,
      POLICY_SERVICE_BASE_URL: "http://localhost:3101",
      COMMAND_FEE_SCHEDULE_JSON: JSON.stringify(scheduleB)
    },
    fetchImpl,
    writeCommandCenterAuditEvent: async () => {},
  });
  const payload = { intent: "join hangout", subjectDid: "did:example:fee-compare" };
  const resA = await appA.inject({ method: "POST", url: "/v1/command/plan", payload });
  const resB = await appB.inject({ method: "POST", url: "/v1/command/plan", payload });
  assert.equal(resA.statusCode, 200);
  assert.equal(resB.statusCode, 200);
  const bodyA = resA.json();
  const bodyB = resB.json();
  assert.notEqual(bodyA.feeScheduleFingerprint, bodyB.feeScheduleFingerprint);
  assert.notEqual(bodyA.planDeterminismKey, bodyB.planDeterminismKey);
  await appA.close();
  await appB.close();
});

await run("command plan determinism key changes when payments receiver changes", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const fetchImpl = async (input) => {
    const url = String(input);
    if (url.includes("/v1/requirements")) {
      return new Response(JSON.stringify({ version: 1, requirements: [] }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }
    return new Response(JSON.stringify({ decision: "DENY", reasons: ["proof_missing"] }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };
  const schedule = {
    version: 1,
    assets: { HBAR: { kind: "HBAR", symbol: "HBAR", decimals: 8 } },
    fees: {
      "action:sync.hangout.join_session": [{ asset: "HBAR", amount: "0.05", purpose: "action.exec" }]
    }
  };
  const appA = buildServer({
    configOverride: {
      ...config,
      POLICY_SERVICE_BASE_URL: "http://localhost:3101",
      COMMAND_FEE_SCHEDULE_JSON: JSON.stringify(schedule),
      PAYMENTS_RECEIVER_ACCOUNT_ID_TESTNET: "0.0.7001"
    },
    fetchImpl,
    writeCommandCenterAuditEvent: async () => {},
  });
  const appB = buildServer({
    configOverride: {
      ...config,
      POLICY_SERVICE_BASE_URL: "http://localhost:3101",
      COMMAND_FEE_SCHEDULE_JSON: JSON.stringify(schedule),
      PAYMENTS_RECEIVER_ACCOUNT_ID_TESTNET: "0.0.7002"
    },
    fetchImpl,
    writeCommandCenterAuditEvent: async () => {},
  });
  const payload = { intent: "join hangout", subjectDid: "did:example:payments-cfg" };
  const resA = await appA.inject({ method: "POST", url: "/v1/command/plan", payload });
  const resB = await appB.inject({ method: "POST", url: "/v1/command/plan", payload });
  assert.equal(resA.statusCode, 200);
  assert.equal(resB.statusCode, 200);
  const bodyA = resA.json();
  const bodyB = resB.json();
  assert.notEqual(bodyA.paymentsConfigFingerprint, bodyB.paymentsConfigFingerprint);
  assert.notEqual(bodyA.planDeterminismKey, bodyB.planDeterminismKey);
  assert.deepEqual(bodyA.action_plan, bodyB.action_plan);
  assert.deepEqual(bodyA.required_capabilities, bodyB.required_capabilities);
  assert.deepEqual(bodyA.next_best_actions, bodyB.next_best_actions);
  await appA.close();
  await appB.close();
});

await run("command plan determinism key changes when memo cap changes", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const fetchImpl = async (input) => {
    const url = String(input);
    if (url.includes("/v1/requirements")) {
      return new Response(JSON.stringify({ version: 1, requirements: [] }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }
    return new Response(JSON.stringify({ decision: "DENY", reasons: ["proof_missing"] }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };
  const schedule = {
    version: 1,
    assets: { HBAR: { kind: "HBAR", symbol: "HBAR", decimals: 8 } },
    fees: {
      "action:sync.hangout.join_session": [{ asset: "HBAR", amount: "0.05", purpose: "action.exec" }]
    }
  };
  const appA = buildServer({
    configOverride: {
      ...config,
      POLICY_SERVICE_BASE_URL: "http://localhost:3101",
      COMMAND_FEE_SCHEDULE_JSON: JSON.stringify(schedule),
      PAYMENTS_RECEIVER_ACCOUNT_ID_TESTNET: "0.0.7001",
      HEDERA_TX_MEMO_MAX_BYTES: 64
    },
    fetchImpl,
    writeCommandCenterAuditEvent: async () => {},
  });
  const appB = buildServer({
    configOverride: {
      ...config,
      POLICY_SERVICE_BASE_URL: "http://localhost:3101",
      COMMAND_FEE_SCHEDULE_JSON: JSON.stringify(schedule),
      PAYMENTS_RECEIVER_ACCOUNT_ID_TESTNET: "0.0.7001",
      HEDERA_TX_MEMO_MAX_BYTES: 120
    },
    fetchImpl,
    writeCommandCenterAuditEvent: async () => {},
  });
  const payload = { intent: "join hangout", subjectDid: "did:example:payments-cfg" };
  const resA = await appA.inject({ method: "POST", url: "/v1/command/plan", payload });
  const resB = await appB.inject({ method: "POST", url: "/v1/command/plan", payload });
  assert.equal(resA.statusCode, 200);
  assert.equal(resB.statusCode, 200);
  const bodyA = resA.json();
  const bodyB = resB.json();
  assert.notEqual(bodyA.paymentsConfigFingerprint, bodyB.paymentsConfigFingerprint);
  assert.notEqual(bodyA.planDeterminismKey, bodyB.planDeterminismKey);
  await appA.close();
  await appB.close();
});

await run("command plan uses empty fee schedule when schedule JSON is invalid", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const app = buildServer({
    configOverride: {
      ...config,
      POLICY_SERVICE_BASE_URL: "http://localhost:3101",
      COMMAND_FEE_SCHEDULE_JSON: "{invalid-json"
    },
    fetchImpl: async () =>
      new Response(JSON.stringify({ version: 1, requirements: [] }), {
        status: 200,
        headers: { "content-type": "application/json" }
      }),
    writeCommandCenterAuditEvent: async () => {},
  });
  const response = await app.inject({
    method: "POST",
    url: "/v1/command/plan",
    payload: { intent: "join hangout", subjectDid: "did:example:invalid-schedule" }
  });
  assert.equal(response.statusCode, 200);
  const body = response.json();
  assert.equal(body.feeQuote, null);
  assert.equal(body.feeQuoteFingerprint, null);
  assert.ok(typeof body.feeScheduleFingerprint === "string");
  await app.close();
});

await run("command plan keeps requirements and next actions in stable order", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const fetchImpl = async (input) => {
    const url = String(input);
    if (url.includes("/v1/requirements")) {
      return new Response(
        JSON.stringify({
          version: 9,
          requirements: [
            { vct: "z.capability", label: "Zeta" },
            { vct: "a.capability", label: "Alpha" },
            { vct: "a.capability", label: "Beta" }
          ]
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    }
    return new Response(JSON.stringify({ decision: "DENY", reasons: ["proof_missing"] }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };
  const app = buildServer({
    configOverride: {
      ...config,
      POLICY_SERVICE_BASE_URL: "http://localhost:3101",
      VERIFIER_SERVICE_BASE_URL: "http://localhost:3102"
    },
    fetchImpl,
    writeCommandCenterAuditEvent: async () => {},
  });
  const response = await app.inject({
    method: "POST",
    url: "/v1/command/plan",
    payload: { intent: "join hangout", subjectDid: "did:example:bob" }
  });
  assert.equal(response.statusCode, 200);
  const body = response.json();
  assert.deepEqual(
    body.required_capabilities.map((entry) => `${entry.vct}:${entry.label}`),
    ["a.capability:Alpha", "a.capability:Beta", "z.capability:Zeta"]
  );
  assert.deepEqual(body.next_best_actions, [
    "Load pulse cards",
    "Join active space",
    "Request realtime token"
  ]);
  await app.close();
});

await run("command plan denies on dependency timeout without hanging", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const fetchImpl = async (_input, init) =>
    await new Promise((_resolve, reject) => {
      const signal = init?.signal;
      const fallback = setTimeout(() => reject(new Error("planner_timeout_fallback")), 1200);
      signal?.addEventListener(
        "abort",
        () => {
          clearTimeout(fallback);
          reject(new Error("aborted"));
        },
        { once: true }
      );
    });
  const app = buildServer({
    configOverride: {
      ...config,
      POLICY_SERVICE_BASE_URL: "http://localhost:3101",
      COMMAND_PLANNER_REQUIREMENTS_TIMEOUT_MS: 100
    },
    fetchImpl,
    writeCommandCenterAuditEvent: async () => {},
  });
  const startedAt = Date.now();
  const response = await app.inject({
    method: "POST",
    url: "/v1/command/plan",
    payload: { intent: "join hangout", subjectDid: "did:example:timeout" }
  });
  const elapsedMs = Date.now() - startedAt;
  assert.equal(response.statusCode, 200);
  const body = response.json();
  assert.equal(body.ready_state, "DENIED");
  assert.equal(body.deny_reason, "dependency_unavailable");
  assert.ok(elapsedMs < 2000, `expected bounded timeout; elapsedMs=${elapsedMs}`);
  await app.close();
});

await run("command plan emits redacted audit event", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const auditEvents = [];
  const fetchImpl = async (input) => {
    const url = String(input);
    if (url.includes("/v1/requirements")) {
      return new Response(JSON.stringify({ version: 3, requirements: [] }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }
    return new Response(JSON.stringify({ decision: "DENY", reasons: ["kb_jwt_missing"] }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };
  const app = buildServer({
    configOverride: {
      ...config,
      POLICY_SERVICE_BASE_URL: "http://localhost:3101",
      VERIFIER_SERVICE_BASE_URL: "http://localhost:3102"
    },
    fetchImpl,
    writeCommandCenterAuditEvent: async (event) => {
      auditEvents.push(event);
    },
  });
  const payload = {
    intent: "join hangout",
    subjectDid: "did:example:redacted",
    proof: {
      presentation: "super-sensitive-presentation",
      nonce: "nonce-sensitive",
      audience: "aud-sensitive"
    }
  };
  const response = await app.inject({ method: "POST", url: "/v1/command/plan", payload });
  assert.equal(response.statusCode, 200);
  assert.equal(auditEvents.length, 1);
  const event = auditEvents[0];
  assert.equal(event.eventType, "command_plan_requested");
  assert.ok(typeof event.subjectHash === "string" && event.subjectHash.length > 0);
  assert.notEqual(event.subjectHash, payload.subjectDid);
  const serialized = JSON.stringify(event.payload);
  assert.ok(!serialized.includes(payload.subjectDid));
  assert.ok(!serialized.includes(payload.proof.presentation));
  assert.ok(!serialized.includes(payload.proof.nonce));
  assert.ok(!serialized.includes(payload.proof.audience));
  await app.close();
});

await run("command audit cleanup respects retention and bounded batches", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const { getDb } = await import("../db.ts");
  let db;
  try {
    db = await getDb();
    await db.raw("select 1");
  } catch {
    console.log("skipped - command audit cleanup respects retention and bounded batches (database unavailable)");
    return;
  }
  await db("command_center_audit_events").where("subject_hash", "like", "cleanup_test_%").del();
  const oldCreatedAt = new Date(Date.now() - 120 * 24 * 60 * 60 * 1000).toISOString();
  const newCreatedAt = new Date().toISOString();
  const oldRows = Array.from({ length: 7 }, (_, index) => ({
    id: `44444444-4444-4444-8444-${String(index).padStart(12, "0")}`,
    created_at: oldCreatedAt,
    subject_hash: "cleanup_test_subject",
    event_type: "command_plan_requested",
    payload_json: {}
  }));
  const newRows = Array.from({ length: 2 }, (_, index) => ({
    id: `55555555-5555-4555-8555-${String(index).padStart(12, "0")}`,
    created_at: newCreatedAt,
    subject_hash: "cleanup_test_subject",
    event_type: "command_plan_requested",
    payload_json: {}
  }));
  await db("command_center_audit_events").insert([...oldRows, ...newRows]);
  const app = buildServer({
    configOverride: {
      ...config,
      COMMAND_AUDIT_CLEANUP_ENABLED: true,
      COMMAND_AUDIT_RETENTION_DAYS: 90,
      COMMAND_AUDIT_CLEANUP_BATCH_SIZE: 2,
      COMMAND_AUDIT_CLEANUP_THROTTLE_MS: 1
    },
    fetchImpl: async () =>
      new Response(JSON.stringify({ error: "unused" }), {
        status: 500,
        headers: { "content-type": "application/json" }
      }),
  });
  await app.inject({
    method: "POST",
    url: "/v1/command/plan",
    payload: { intent: "join hangout", subjectDid: "did:example:cleanup" }
  });
  await new Promise((resolve) => setTimeout(resolve, 200));
  const oldAfterFirst = await db("command_center_audit_events")
    .where({ subject_hash: "cleanup_test_subject" })
    .andWhere("created_at", "<", newCreatedAt)
    .count({ count: "*" })
    .first();
  assert.equal(Number(oldAfterFirst?.count ?? 0), 1);
  await new Promise((resolve) => setTimeout(resolve, 5));
  await app.inject({
    method: "POST",
    url: "/v1/command/plan",
    payload: { intent: "join hangout", subjectDid: "did:example:cleanup-2" }
  });
  await new Promise((resolve) => setTimeout(resolve, 200));
  const oldAfterSecond = await db("command_center_audit_events")
    .where({ subject_hash: "cleanup_test_subject" })
    .andWhere("created_at", "<", newCreatedAt)
    .count({ count: "*" })
    .first();
  const newRemaining = await db("command_center_audit_events")
    .where({ subject_hash: "cleanup_test_subject" })
    .andWhere("created_at", ">=", newCreatedAt)
    .count({ count: "*" })
    .first();
  assert.equal(Number(oldAfterSecond?.count ?? 0), 0);
  assert.equal(Number(newRemaining?.count ?? 0), 2);
  await app.close();
});

await run("command plan returns promptly when audit cleanup hangs", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const app = buildServer({
    configOverride: { ...config },
    writeCommandCenterAuditEvent: async () => {},
    maybeCleanupCommandCenterAuditEvents: async () => await new Promise(() => {}),
    fetchImpl: async () =>
      new Response(JSON.stringify({ error: "unused" }), {
        status: 500,
        headers: { "content-type": "application/json" }
      }),
  });
  const startedAt = Date.now();
  const response = await app.inject({
    method: "POST",
    url: "/v1/command/plan",
    payload: { intent: "join hangout", subjectDid: "did:example:hang" }
  });
  const elapsedMs = Date.now() - startedAt;
  assert.equal(response.statusCode, 200);
  assert.ok(elapsedMs < 1500, `planner should not block on cleanup; elapsedMs=${elapsedMs}`);
  await app.close();
});

await run("command plan swallows cleanup rejection without unhandled failure", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const app = buildServer({
    configOverride: { ...config },
    writeCommandCenterAuditEvent: async () => {},
    maybeCleanupCommandCenterAuditEvents: async () => {
      throw new Error("cleanup_failed");
    },
    fetchImpl: async () =>
      new Response(JSON.stringify({ error: "unused" }), {
        status: 500,
        headers: { "content-type": "application/json" }
      }),
  });
  const response = await app.inject({
    method: "POST",
    url: "/v1/command/plan",
    payload: { intent: "join hangout", subjectDid: "did:example:reject" }
  });
  assert.equal(response.statusCode, 200);
  await app.close();
});
