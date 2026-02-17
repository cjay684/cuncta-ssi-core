import { FastifyInstance, FastifyRequest } from "fastify";
import { randomUUID, createHash, randomBytes } from "node:crypto";
import { SignJWT } from "jose";
import { z } from "zod";
import {
  createHmacSha256Pseudonymizer,
  hashCanonicalJson,
  makeErrorResponse,
  signAnchorMeta
} from "@cuncta/shared";
import { config } from "../config.js";
import { getDb } from "../db.js";
import { metrics } from "../metrics.js";
import { log } from "../log.js";
import { requireServiceAuth } from "../auth.js";

const pseudonymizer = createHmacSha256Pseudonymizer({ pepper: config.PSEUDONYMIZER_PEPPER });
const textEncoder = new TextEncoder();
const hashHex = (value: string) => createHash("sha256").update(value).digest("hex");

const createServiceJwt = async (input: {
  audience: string;
  secret: string;
  ttlSeconds: number;
  scope: string[] | string;
}) => {
  const nowSeconds = Math.floor(Date.now() / 1000);
  return new SignJWT({
    aud: input.audience,
    scope: input.scope,
    iat: nowSeconds,
    exp: nowSeconds + input.ttlSeconds,
    iss: "app-gateway",
    sub: "app-gateway"
  })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .sign(textEncoder.encode(input.secret));
};

const profileSchema = z.object({
  subjectDid: z.string().min(3),
  handle: z.string().trim().min(1).max(64),
  displayName: z.string().trim().max(80).optional(),
  bio: z.string().trim().max(300).optional(),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});

const postSchema = z.object({
  subjectDid: z.string().min(3),
  content: z.string().trim().min(1).max(4000),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});

const replySchema = z.object({
  subjectDid: z.string().min(3),
  postId: z.string().uuid(),
  content: z.string().trim().min(1).max(2000),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});

const followSchema = z.object({
  subjectDid: z.string().min(3),
  followeeDid: z.string().min(3),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});

const reportSchema = z.object({
  subjectDid: z.string().min(3),
  targetPostId: z.string().uuid().optional(),
  targetReplyId: z.string().uuid().optional(),
  spaceId: z.string().uuid().optional(),
  targetSpacePostId: z.string().uuid().optional(),
  reasonCode: z.string().trim().min(2).max(64),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});

const spaceCreateSchema = z.object({
  subjectDid: z.string().min(3),
  slug: z
    .string()
    .trim()
    .toLowerCase()
    .regex(/^[a-z0-9-]{3,64}$/),
  displayName: z.string().trim().min(2).max(80),
  description: z.string().trim().max(500).optional(),
  policyPackId: z.string().trim().min(3).max(120).default("space.default.v1"),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});

const spaceJoinSchema = z.object({
  subjectDid: z.string().min(3),
  spaceId: z.string().uuid(),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});

const spacePostSchema = z.object({
  subjectDid: z.string().min(3),
  spaceId: z.string().uuid(),
  content: z.string().trim().min(1).max(4000),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});

const spaceModerateSchema = z.object({
  subjectDid: z.string().min(3),
  spaceId: z.string().uuid(),
  operation: z.enum(["remove_content", "restrict_member"]),
  targetSpacePostId: z.string().uuid().optional(),
  targetSubjectDid: z.string().min(3).optional(),
  reasonCode: z.string().trim().min(2).max(64),
  anchor: z.boolean().optional().default(false),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});

const trustLensSchema = z.enum(["verified_only", "trusted_creator", "space_members"]);
const safetyModeSchema = z.enum(["strict"]);

const spaceFeedQuerySchema = z.object({
  spaceId: z.string().uuid(),
  viewerDid: z.string().min(3).optional(),
  limit: z.coerce.number().int().min(1).max(50).default(20)
});
const spaceFlowQuerySchema = z.object({
  spaceId: z.string().uuid(),
  viewerDid: z.string().min(3).optional(),
  limit: z.coerce.number().int().min(1).max(50).default(20),
  trust: trustLensSchema.optional(),
  safety: safetyModeSchema.optional()
});

const spacesQuerySchema = z.object({
  search: z.string().trim().max(80).optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50)
});

const spaceModerationCasesQuerySchema = z.object({
  subjectDid: z.string().min(3),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});

const spaceModerationCaseResolveSchema = z.object({
  subjectDid: z.string().min(3),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3),
  anchor: z.boolean().optional().default(false)
});

const spaceParamsSchema = z.object({
  spaceId: z.string().uuid()
});

const moderationCaseParamsSchema = z.object({
  spaceId: z.string().uuid(),
  caseId: z.string().uuid()
});
const moderationAuditQuerySchema = z.object({
  subjectDid: z.string().min(3),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3),
  limit: z.coerce.number().int().min(1).max(100).default(50)
});
const spaceAnalyticsQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(90).default(30)
});
const emojiCreateSchema = z.object({
  subjectDid: z.string().min(3),
  spaceId: z.string().uuid().optional(),
  assetRef: z.string().trim().min(3).max(500),
  assetHash: z.string().trim().min(8).max(200).optional(),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const emojiPackCreateSchema = z.object({
  subjectDid: z.string().min(3),
  spaceId: z.string().uuid().optional(),
  visibility: z.enum(["private", "space"]).default("private"),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const emojiPackAddSchema = z.object({
  subjectDid: z.string().min(3),
  packId: z.string().uuid(),
  assetId: z.string().uuid(),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const emojiPackPublishSchema = z.object({
  subjectDid: z.string().min(3),
  packId: z.string().uuid(),
  spaceId: z.string().uuid(),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const soundpackCreateSchema = z.object({
  subjectDid: z.string().min(3),
  spaceId: z.string().uuid().optional(),
  visibility: z.enum(["private", "space"]).default("private"),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const soundAssetAddSchema = z.object({
  subjectDid: z.string().min(3),
  packId: z.string().uuid(),
  assetRef: z.string().trim().min(3).max(500),
  assetHash: z.string().trim().min(8).max(200).optional(),
  durationMs: z.number().int().min(0).max(60_000).default(1000),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const soundpackPublishSchema = z.object({
  subjectDid: z.string().min(3),
  packId: z.string().uuid(),
  spaceId: z.string().uuid(),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const soundpackActivateSchema = z.object({
  subjectDid: z.string().min(3),
  packId: z.string().uuid(),
  spaceId: z.string().uuid(),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const presenceSetModeSchema = z.object({
  subjectDid: z.string().min(3),
  spaceId: z.string().uuid(),
  mode: z.enum(["quiet", "active"]),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const presenceInviteSchema = z.object({
  subjectDid: z.string().min(3),
  spaceId: z.string().uuid(),
  inviteeDid: z.string().min(3),
  sessionRef: z.string().trim().min(3).max(200),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const presenceStateQuerySchema = z.object({
  spaceId: z.string().uuid()
});
const watchCreateSessionSchema = z.object({
  subjectDid: z.string().min(3),
  spaceId: z.string().uuid(),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const watchJoinSessionSchema = z.object({
  subjectDid: z.string().min(3),
  sessionId: z.string().uuid(),
  spaceId: z.string().uuid(),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const watchEndSessionSchema = z.object({
  subjectDid: z.string().min(3),
  sessionId: z.string().uuid(),
  spaceId: z.string().uuid(),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const syncCreateSessionSchema = z.object({
  subjectDid: z.string().min(3),
  spaceId: z.string().uuid(),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const syncJoinSessionSchema = z.object({
  subjectDid: z.string().min(3),
  sessionId: z.string().uuid(),
  spaceId: z.string().uuid(),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const syncEventPayloadSchema = z.object({
  sessionId: z.string().uuid(),
  permissionToken: z.string().min(16),
  eventType: z.enum(["SCROLL_SYNC", "LISTEN_STATE", "REACTION", "HEARTBEAT"]),
  payload: z.unknown()
});
const syncSessionStreamParamsSchema = z.object({
  sessionId: z.string().uuid()
});
const syncSessionStreamQuerySchema = z.object({
  permission_token: z.string().min(16)
});
const syncSessionReportV02Schema = z.object({
  subjectDid: z.string().min(3),
  sessionId: z.string().uuid(),
  spaceId: z.string().uuid(),
  reasonCode: z.string().trim().min(2).max(64),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const syncSessionModerateV02Schema = z.object({
  subjectDid: z.string().min(3),
  sessionId: z.string().uuid(),
  spaceId: z.string().uuid(),
  operation: z.enum(["kick_participant", "end_session"]),
  targetSubjectDid: z.string().min(3).optional(),
  reasonCode: z.string().trim().min(2).max(64),
  anchor: z.boolean().optional().default(false),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const mediaAssetReportSchema = z.object({
  subjectDid: z.string().min(3),
  spaceId: z.string().uuid(),
  assetId: z.string().uuid(),
  reasonCode: z.string().trim().min(2).max(64),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const mediaAssetModerateSchema = z.object({
  subjectDid: z.string().min(3),
  spaceId: z.string().uuid(),
  caseId: z.string().uuid().optional(),
  assetId: z.string().uuid().optional(),
  resolution: z.enum(["ACK", "RESOLVED"]).default("RESOLVED"),
  reasonCode: z.string().trim().min(2).max(64).default("asset_moderated"),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const syncSessionReportSchema = z.object({
  subjectDid: z.string().min(3),
  spaceId: z.string().uuid(),
  sessionId: z.string().uuid(),
  reasonCode: z.string().trim().min(2).max(64),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const syncSessionModerateSchema = z.object({
  subjectDid: z.string().min(3),
  spaceId: z.string().uuid(),
  caseId: z.string().uuid(),
  resolution: z.enum(["ACK", "RESOLVED"]).default("RESOLVED"),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});

const feedQuerySchema = z.object({
  viewerDid: z.string().min(3).optional(),
  limit: z.coerce.number().int().min(1).max(50).default(20)
});

const flowFeedQuerySchema = z.object({
  viewerDid: z.string().min(3).optional(),
  limit: z.coerce.number().int().min(1).max(50).default(20),
  trust: trustLensSchema.optional(),
  safety: safetyModeSchema.optional()
});
const explainPostParamsSchema = z.object({
  postId: z.string().uuid()
});
const explainPostQuerySchema = z.object({
  viewerDid: z.string().min(3).optional(),
  trust: trustLensSchema.optional(),
  safety: safetyModeSchema.optional(),
  feedMode: z.enum(["signal", "flow"]).optional()
});

type FunnelAction =
  | "profile_create"
  | "post"
  | "reply"
  | "follow"
  | "report"
  | "space_create"
  | "space_join"
  | "space_post"
  | "space_moderate"
  | "emoji_create"
  | "emoji_pack_create"
  | "emoji_pack_publish"
  | "emoji_asset_report"
  | "soundpack_create"
  | "soundpack_publish"
  | "soundpack_activate"
  | "presence_set_mode"
  | "presence_invite"
  | "watch_create"
  | "watch_join"
  | "watch_end"
  | "scroll_create"
  | "scroll_join"
  | "scroll_event"
  | "scroll_end"
  | "listen_create"
  | "listen_join"
  | "listen_event"
  | "listen_end";
type PrivacyStatus = { restricted: boolean; tombstoned: boolean };
type VerifyResponse = {
  decision?: "ALLOW" | "DENY";
  reasons?: string[];
  policy_id?: string;
  policy_version?: number;
};
type RequirementsResponse = {
  policyId?: string;
  version?: number;
  policyHash?: string;
  requirements?: Array<{ vct: string; label?: string }>;
  context?: Record<string, unknown>;
};

type RequirementSummary = { vct: string; label: string };
type SpaceModerationCaseStatus = "OPEN" | "ACK" | "RESOLVED";

const requirementLabels: Record<string, string> = {
  "cuncta.social.account_active": "Active social account",
  "cuncta.social.can_post": "Ability to post",
  "cuncta.social.can_comment": "Ability to reply",
  "cuncta.social.trusted_creator": "Trusted Creator",
  "cuncta.social.space.member": "Space member",
  "cuncta.social.space.poster": "Space poster",
  "cuncta.social.space.moderator": "Space moderator",
  "cuncta.social.space.steward": "Space steward",
  "cuncta.media.emoji_creator": "Emoji creator",
  "cuncta.media.soundpack_creator": "Soundpack creator",
  "cuncta.sync.watch_host": "Watch host",
  "cuncta.presence.mode_access": "Presence mode access",
  "cuncta.sync.scroll_host": "Scroll host",
  "cuncta.sync.listen_host": "Listen host",
  "cuncta.sync.session_participant": "Sync session participant"
};

const requirementLabel = (vct: string, label?: string) => label ?? requirementLabels[vct] ?? vct;
const tierRank: Record<string, number> = { bronze: 0, silver: 1, gold: 2 };

const normalizeTier = (value: unknown) => {
  const normalized = String(value ?? "bronze").toLowerCase();
  if (normalized === "gold" || normalized === "silver" || normalized === "bronze")
    return normalized;
  return "bronze";
};

const parseAuraState = (raw: unknown): Record<string, unknown> => {
  if (raw && typeof raw === "object") return raw as Record<string, unknown>;
  if (typeof raw === "string") {
    try {
      const parsed = JSON.parse(raw) as unknown;
      return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : {};
    } catch {
      return {};
    }
  }
  return {};
};

const inferAuraThreshold = (vct: string) => {
  if (vct === "cuncta.social.space.poster") return "Bronze Aura tier or higher";
  if (vct === "cuncta.social.space.moderator" || vct === "cuncta.social.trusted_creator") {
    return "Silver Aura tier or higher";
  }
  return null;
};

const funnel: Record<
  FunnelAction,
  { attempts: number; allowed: number; denied: number; completed: number }
> = {
  profile_create: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  post: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  reply: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  follow: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  report: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  space_create: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  space_join: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  space_post: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  space_moderate: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  emoji_create: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  emoji_pack_create: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  emoji_pack_publish: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  emoji_asset_report: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  soundpack_create: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  soundpack_publish: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  soundpack_activate: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  presence_set_mode: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  presence_invite: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  watch_create: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  watch_join: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  watch_end: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  scroll_create: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  scroll_join: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  scroll_event: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  scroll_end: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  listen_create: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  listen_join: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  listen_event: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  listen_end: { attempts: 0, allowed: 0, denied: 0, completed: 0 }
};

const incAttempt = (action: FunnelAction) => {
  funnel[action].attempts += 1;
  metrics.incCounter("social_action_attempt_total", { action });
};
const incAllowed = (action: FunnelAction) => {
  funnel[action].allowed += 1;
  metrics.incCounter("social_action_allowed_total", { action });
};
const incDenied = (action: FunnelAction) => {
  funnel[action].denied += 1;
  metrics.incCounter("social_action_denied_total", { action });
};
const incCompleted = (action: FunnelAction) => {
  funnel[action].completed += 1;
  metrics.incCounter("social_action_completed_total", { action });
};

type SyncSubscriberSocket = { send: (message: string) => void };
type SyncSubscriber = {
  socket: SyncSubscriberSocket;
  subjectDidHash: string;
  permissionHash: string;
};
const syncSubscribers = new Map<string, Set<SyncSubscriber>>();
const syncEventBuckets = new Map<string, { windowMs: number; count: number; startedAt: number }>();
let syncEventLastRetentionPruneAt = 0;

const addSyncSubscriber = (sessionId: string, subscriber: SyncSubscriber) => {
  const existing = syncSubscribers.get(sessionId) ?? new Set<SyncSubscriber>();
  existing.add(subscriber);
  syncSubscribers.set(sessionId, existing);
};

const removeSyncSubscriber = (sessionId: string, subscriber: SyncSubscriber) => {
  const existing = syncSubscribers.get(sessionId);
  if (!existing) return;
  existing.delete(subscriber);
  if (existing.size === 0) {
    syncSubscribers.delete(sessionId);
  }
};

const broadcastSyncEvent = (sessionId: string, payload: Record<string, unknown>) => {
  const existing = syncSubscribers.get(sessionId);
  if (!existing || existing.size === 0) return;
  const message = JSON.stringify(payload);
  for (const subscriber of existing) {
    try {
      subscriber.socket.send(message);
    } catch {
      removeSyncSubscriber(sessionId, subscriber);
    }
  }
};

const pruneExpiredSyncEvents = async () => {
  const now = Date.now();
  if (now - syncEventLastRetentionPruneAt < 60_000) return;
  syncEventLastRetentionPruneAt = now;
  const db = await getDb();
  const retentionCutoff = new Date(
    now - config.SYNC_SESSION_EVENT_RETENTION_DAYS * 24 * 60 * 60 * 1000
  ).toISOString();
  await db("sync_session_events").where("created_at", "<", retentionCutoff).del();
};

const mintSyncPermissionToken = async (input: { sessionId: string; subjectDidHash: string }) => {
  const permissionId = randomUUID();
  const rawToken = randomBytes(32).toString("base64url");
  const permissionHash = hashHex(rawToken);
  const expiresAt = new Date(
    Date.now() + config.SYNC_SESSION_PERMISSION_TTL_SECONDS * 1000
  ).toISOString();
  await (
    await getDb()
  )("sync_session_permissions").insert({
    permission_id: permissionId,
    session_id: input.sessionId,
    subject_did_hash: input.subjectDidHash,
    expires_at: expiresAt,
    permission_hash: permissionHash,
    created_at: new Date().toISOString()
  });
  return { token: rawToken, permissionHash, expiresAt };
};

const getSyncSession = async (sessionId: string) => {
  return (await (await getDb())("sync_sessions").where({ session_id: sessionId }).first()) as
    | {
        session_id: string;
        space_id: string;
        kind: "scroll" | "listen";
        host_subject_did_hash: string;
        status: "ACTIVE" | "ENDED";
        policy_pack_id?: string | null;
      }
    | undefined;
};

const ensureSyncSessionAccess = async (input: {
  sessionId: string;
  spaceId: string;
  expectedKind?: "scroll" | "listen";
}) => {
  const session = await getSyncSession(input.sessionId);
  if (!session) {
    return {
      error: makeErrorResponse("invalid_request", "Session not found", { devMode: config.DEV_MODE })
    };
  }
  if (session.space_id !== input.spaceId) {
    return {
      error: makeErrorResponse("invalid_request", "Session context mismatch", {
        devMode: config.DEV_MODE
      })
    };
  }
  if (input.expectedKind && session.kind !== input.expectedKind) {
    return {
      error: makeErrorResponse("invalid_request", "Session kind mismatch", {
        devMode: config.DEV_MODE
      })
    };
  }
  return { session };
};

const validateSyncPermission = async (input: {
  sessionId: string;
  permissionToken: string;
  expectedSubjectDidHash?: string;
}) => {
  const permissionHash = hashHex(input.permissionToken);
  const row = await (await getDb())("sync_session_permissions")
    .where({ permission_hash: permissionHash, session_id: input.sessionId })
    .first();
  if (!row) return { ok: false as const, reason: "permission_invalid" };
  if (new Date(String(row.expires_at)).getTime() <= Date.now()) {
    return { ok: false as const, reason: "permission_expired" };
  }
  if (input.expectedSubjectDidHash && row.subject_did_hash !== input.expectedSubjectDidHash) {
    return { ok: false as const, reason: "permission_subject_mismatch" };
  }
  const privacy = await checkWriterPrivacy(String(row.subject_did_hash));
  if (privacy.restricted || privacy.tombstoned) {
    return { ok: false as const, reason: "privacy_restricted" };
  }
  return {
    ok: true as const,
    subjectDidHash: String(row.subject_did_hash),
    permissionHash
  };
};

const hasActiveSpaceMembership = async (spaceId: string, subjectDidHash: string) => {
  const row = await (await getDb())("social_space_memberships")
    .where({ space_id: spaceId, subject_did_hash: subjectDidHash, status: "ACTIVE" })
    .first();
  return Boolean(row);
};

const getTierRateLimit = (tier: string) => {
  if (tier === "gold") return config.SYNC_SESSION_EVENT_RATE_GOLD_PER_SEC;
  if (tier === "silver") return config.SYNC_SESSION_EVENT_RATE_SILVER_PER_SEC;
  return config.SYNC_SESSION_EVENT_RATE_BRONZE_PER_SEC;
};

const resolveSubjectTier = async (subjectDidHash: string, spaceId: string) => {
  const db = await getDb();
  const spaceRow = await db("aura_state")
    .where({ subject_did_hash: subjectDidHash, domain: `space:${spaceId}` })
    .first();
  const socialRow = await db("aura_state")
    .where({ subject_did_hash: subjectDidHash, domain: "social" })
    .first();
  const source = spaceRow ?? socialRow;
  if (!source) return "bronze";
  const state = parseAuraState(source.state);
  return normalizeTier(state.tier);
};

const checkSyncEventRateLimit = async (input: {
  permissionHash: string;
  subjectDidHash: string;
  spaceId: string;
}) => {
  const tier = await resolveSubjectTier(input.subjectDidHash, input.spaceId);
  const maxPerSecond = getTierRateLimit(tier);
  const burst = maxPerSecond * config.SYNC_SESSION_EVENT_BURST_MULTIPLIER;
  const now = Date.now();
  const bucket = syncEventBuckets.get(input.permissionHash);
  if (!bucket || now - bucket.startedAt >= 1000) {
    syncEventBuckets.set(input.permissionHash, { windowMs: 1000, count: 1, startedAt: now });
    return { allowed: true as const, tier };
  }
  if (bucket.count >= burst) {
    return { allowed: false as const, tier };
  }
  bucket.count += 1;
  return { allowed: true as const, tier };
};

const getIssuerServiceSecret = () =>
  config.SERVICE_JWT_SECRET_ISSUER ??
  (config.ALLOW_LEGACY_SERVICE_JWT_SECRET ? config.SERVICE_JWT_SECRET : undefined);

const getPrivacyStatus = async (subjectDidHash: string): Promise<PrivacyStatus> => {
  const serviceSecret = getIssuerServiceSecret();
  if (!serviceSecret) {
    throw new Error("issuer_service_auth_unavailable");
  }
  const token = await createServiceJwt({
    audience: config.SERVICE_JWT_AUDIENCE_ISSUER ?? config.SERVICE_JWT_AUDIENCE,
    secret: serviceSecret,
    ttlSeconds: config.SERVICE_JWT_TTL_SECONDS,
    scope: ["issuer:privacy_status"]
  });
  const url = new URL("/v1/internal/privacy/status", config.ISSUER_SERVICE_BASE_URL);
  url.searchParams.set("subjectDidHash", subjectDidHash);
  const response = await fetch(url, {
    method: "GET",
    headers: { Authorization: `Bearer ${token}` }
  });
  if (!response.ok) {
    throw new Error("issuer_privacy_status_unavailable");
  }
  const payload = (await response.json()) as PrivacyStatus;
  return { restricted: Boolean(payload.restricted), tombstoned: Boolean(payload.tombstoned) };
};

const getRequirements = async (actionId: string, context?: Record<string, unknown>) => {
  const url = new URL("/v1/requirements", config.APP_GATEWAY_BASE_URL);
  url.searchParams.set("action", actionId);
  if (typeof context?.space_id === "string" && context.space_id.length > 0) {
    url.searchParams.set("space_id", context.space_id);
  }
  const response = await fetch(url, { method: "GET" });
  if (!response.ok) throw new Error("requirements_unavailable");
  const payload = (await response.json().catch(() => ({}))) as RequirementsResponse;
  const vct = payload.requirements?.[0]?.vct;
  if (!vct) throw new Error("requirements_missing");
  return {
    vct,
    label: requirementLabel(vct, payload.requirements?.[0]?.label),
    policyId: payload.policyId ?? null,
    policyVersion: payload.version ?? null,
    policyHash: payload.policyHash ?? null,
    context: payload.context ?? undefined,
    requirements: (payload.requirements ?? []).map((entry) => ({
      vct: entry.vct,
      label: requirementLabel(entry.vct, entry.label)
    }))
  };
};

const verifyAction = async (input: {
  actionId: string;
  presentation: string;
  nonce: string;
  audience: string;
  context?: Record<string, unknown>;
}) => {
  const url = new URL("/v1/verify", config.APP_GATEWAY_BASE_URL);
  url.searchParams.set("action", input.actionId);
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      presentation: input.presentation,
      nonce: input.nonce,
      audience: input.audience,
      context: input.context
    })
  });
  if (!response.ok) {
    return { decision: "DENY" as const, reasons: ["verify_unavailable"] };
  }
  const payload = (await response.json().catch(() => ({}))) as VerifyResponse;
  return {
    decision: payload.decision === "ALLOW" ? "ALLOW" : "DENY",
    reasons: payload.reasons ?? [],
    policyId: payload.policy_id ?? null,
    policyVersion: payload.policy_version ?? null
  };
};

const logAction = async (input: {
  subjectDidHash: string;
  actionType: string;
  decision: "ALLOW" | "DENY" | "ATTEMPT" | "COMPLETE";
  policyId?: string | null;
  policyVersion?: number | null;
}) => {
  const db = await getDb();
  await db("social_action_log").insert({
    subject_did_hash: input.subjectDidHash,
    action_type: input.actionType,
    decision: input.decision,
    policy_id: input.policyId ?? null,
    policy_version: input.policyVersion ?? null,
    created_at: new Date().toISOString()
  });
};

const purgeSubjectDataOnTombstone = async (subjectDidHash: string) => {
  const db = await getDb();
  const now = new Date().toISOString();
  await db.transaction(async (trx) => {
    await trx("social_profiles")
      .where({ subject_did_hash: subjectDidHash })
      .whereNull("deleted_at")
      .update({ deleted_at: now, updated_at: now, bio: null });
    await trx("social_posts")
      .where({ author_subject_did_hash: subjectDidHash })
      .whereNull("deleted_at")
      .update({ deleted_at: now, content_text: "[erased]" });
    await trx("social_replies")
      .where({ author_subject_did_hash: subjectDidHash })
      .whereNull("deleted_at")
      .update({ deleted_at: now, content_text: "[erased]" });
    await trx("social_follows").where({ follower_subject_did_hash: subjectDidHash }).del();
    await trx("social_follows").where({ followee_subject_did_hash: subjectDidHash }).del();
    await trx("media_emoji_assets")
      .where({ creator_subject_hash: subjectDidHash })
      .whereNull("deleted_at")
      .update({ deleted_at: now, status: "ERASED" });
    await trx("media_emoji_packs")
      .where({ owner_subject_hash: subjectDidHash })
      .update({ published_at: null });
    await trx("media_soundpacks")
      .where({ owner_subject_hash: subjectDidHash })
      .update({ published_at: null });
    await trx("presence_space_states").where({ subject_hash: subjectDidHash }).del();
    await trx("presence_invite_events")
      .where({ inviter_hash: subjectDidHash })
      .update({ status: "ERASED" });
    await trx("presence_invite_events")
      .where({ invitee_hash: subjectDidHash })
      .update({ status: "ERASED" });
    await trx("sync_watch_sessions")
      .where({ host_hash: subjectDidHash })
      .update({ status: "ENDED", ended_at: now });
    await trx("sync_watch_participants")
      .where({ subject_hash: subjectDidHash })
      .update({ left_at: now });
    await trx("sync_sessions")
      .where({ host_subject_did_hash: subjectDidHash })
      .where({ status: "ACTIVE" })
      .update({ status: "ENDED", ended_at: now });
    await trx("sync_session_participants")
      .where({ subject_did_hash: subjectDidHash })
      .whereNull("left_at")
      .update({ left_at: now });
    await trx("sync_session_permissions").where({ subject_did_hash: subjectDidHash }).del();
    await trx("sync_session_events")
      .where({ actor_subject_did_hash: subjectDidHash })
      .update({
        actor_subject_did_hash: hashHex(`erased:${subjectDidHash}`)
      });
    await trx("sync_session_reports")
      .where({ reporter_subject_did_hash: subjectDidHash })
      .update({
        reporter_subject_did_hash: hashHex(`erased:${subjectDidHash}`)
      });
  });
};

const checkWriterPrivacy = async (subjectDidHash: string) => {
  const privacy = await getPrivacyStatus(subjectDidHash);
  if (privacy.tombstoned) {
    await purgeSubjectDataOnTombstone(subjectDidHash).catch(() => undefined);
  }
  return privacy;
};

const verifyAndGate = async (input: {
  subjectDidHash: string;
  actionId: string;
  actionType: FunnelAction;
  presentation: string;
  nonce: string;
  audience: string;
  pinnedPolicyHash?: string | null;
  context?: Record<string, unknown>;
}) => {
  incAttempt(input.actionType);
  await logAction({
    subjectDidHash: input.subjectDidHash,
    actionType: input.actionId,
    decision: "ATTEMPT"
  }).catch(() => undefined);
  const privacy = await checkWriterPrivacy(input.subjectDidHash);
  if (privacy.restricted || privacy.tombstoned) {
    incDenied(input.actionType);
    await logAction({
      subjectDidHash: input.subjectDidHash,
      actionType: input.actionId,
      decision: "DENY"
    }).catch(() => undefined);
    return {
      denied: makeErrorResponse(
        "invalid_request",
        privacy.tombstoned
          ? "This account is erased. Social writes are disabled and content is hidden from feed."
          : "This account is restricted. Social writes are disabled while read access remains available.",
        { devMode: config.DEV_MODE }
      )
    };
  }

  const requirements = await getRequirements(input.actionId, input.context);
  if (
    input.pinnedPolicyHash &&
    requirements.policyHash &&
    requirements.policyHash !== input.pinnedPolicyHash
  ) {
    incDenied(input.actionType);
    await logAction({
      subjectDidHash: input.subjectDidHash,
      actionType: input.actionId,
      decision: "DENY",
      policyId: requirements.policyId,
      policyVersion: requirements.policyVersion
    }).catch(() => undefined);
    return {
      denied: makeErrorResponse(
        "policy_pack_hash_mismatch",
        "Space rules updated; please refresh.",
        {
          devMode: config.DEV_MODE
        }
      )
    };
  }
  const verified = await verifyAction({
    actionId: input.actionId,
    presentation: input.presentation,
    nonce: input.nonce,
    audience: input.audience,
    context: requirements.context ?? input.context
  });
  if (verified.decision !== "ALLOW") {
    incDenied(input.actionType);
    await logAction({
      subjectDidHash: input.subjectDidHash,
      actionType: input.actionId,
      decision: "DENY",
      policyId: verified.policyId,
      policyVersion: verified.policyVersion
    }).catch(() => undefined);
    return {
      denied: {
        decision: "DENY",
        message: `You need the ability required by ${requirements.vct}.`
      }
    };
  }

  incAllowed(input.actionType);
  return {
    allowMeta: {
      policyId: verified.policyId ?? requirements.policyId,
      policyVersion: verified.policyVersion ?? requirements.policyVersion
    }
  };
};

type SpacePolicyPack = {
  policy_pack_id: string;
  display_name?: string | null;
  join_action_id: string;
  post_action_id: string;
  moderate_action_id: string;
  visibility: string;
  join_policy_hash?: string | null;
  post_policy_hash?: string | null;
  moderate_policy_hash?: string | null;
  pinned_policy_hash_join?: string | null;
  pinned_policy_hash_post?: string | null;
  pinned_policy_hash_moderate?: string | null;
};

type SpaceRecord = {
  space_id: string;
  slug: string;
  display_name: string;
  description?: string | null;
  created_by_subject_did_hash: string;
  policy_pack_id: string;
  created_at: string;
  archived_at?: string | null;
};

type SpaceModerationCaseRecord = {
  case_id: string;
  space_id: string;
  report_id: string;
  status: SpaceModerationCaseStatus;
  created_at: string;
  updated_at: string;
};

const getSpacePolicyPack = async (policyPackId: string): Promise<SpacePolicyPack | null> => {
  const db = await getDb();
  const row = (await db("social_space_policy_packs")
    .where({ policy_pack_id: policyPackId })
    .first()) as SpacePolicyPack | undefined;
  return row ?? null;
};

const getSpaceById = async (spaceId: string): Promise<SpaceRecord | null> => {
  const db = await getDb();
  const row = (await db("social_spaces")
    .where({ space_id: spaceId })
    .whereNull("archived_at")
    .first()) as SpaceRecord | undefined;
  return row ?? null;
};

const isSpaceMemberRestricted = async (spaceId: string, subjectDidHash: string) => {
  const db = await getDb();
  const row = await db("social_space_member_restrictions")
    .where({ space_id: spaceId, subject_did_hash: subjectDidHash })
    .first();
  return Boolean(row);
};

const getActionRequirementSummary = async (
  actionId: string,
  context?: Record<string, unknown>
): Promise<RequirementSummary[]> => {
  const requirements = await getRequirements(actionId, context);
  if (requirements.requirements && requirements.requirements.length > 0) {
    return requirements.requirements;
  }
  return [{ vct: requirements.vct, label: requirements.label }];
};

const getSpaceMemberCount = async (spaceId: string) => {
  const db = await getDb();
  const row = await db("social_space_memberships")
    .where({ space_id: spaceId, status: "ACTIVE" })
    .count<{ count: string }>("space_id as count")
    .first();
  return Number(row?.count ?? 0);
};

const summarizeRequirementLabels = (requirements: RequirementSummary[]) =>
  requirements.map((entry) => entry.label).join(", ");

const buildAuraThresholdSummary = (requirements: RequirementSummary[]) => {
  const thresholds = Array.from(
    new Set(
      requirements
        .map((entry) => inferAuraThreshold(entry.vct))
        .filter(
          (value): value is Exclude<ReturnType<typeof inferAuraThreshold>, null> =>
            typeof value === "string" && value.length > 0
        )
    )
  );
  return thresholds;
};

const inferFloorTierFromRequirements = (requirements: RequirementSummary[]) => {
  const needsSilver = requirements.some(
    (entry) =>
      entry.vct === "cuncta.social.trusted_creator" || entry.vct === "cuncta.social.space.moderator"
  );
  return needsSilver ? "silver" : "bronze";
};

const getFlowThresholdTier = (strict: boolean) => {
  const configured = strict
    ? (process.env.SOCIAL_FLOW_STRICT_MIN_TRUST_TIER ?? "silver")
    : (process.env.SOCIAL_FLOW_MIN_TRUST_TIER ?? "bronze");
  return normalizeTier(configured);
};

const getSpaceFlowThresholdTier = (strict: boolean, baselineFloor: string) => {
  const configured = strict
    ? (process.env.SOCIAL_SPACE_FLOW_STRICT_MIN_TRUST_TIER ?? "silver")
    : (process.env.SOCIAL_SPACE_FLOW_MIN_TRUST_TIER ?? baselineFloor);
  const configuredTier = normalizeTier(configured);
  return tierRank[configuredTier] >= tierRank[baselineFloor] ? configuredTier : baselineFloor;
};

const getFlowAntiGaming = async () => {
  const db = await getDb();
  const rows = (await db("aura_rules")
    .whereIn("rule_id", ["social.can_post.v2", "social.trusted_creator.v1"])
    .select("rule_logic")) as Array<{ rule_logic: unknown }>;
  let perCounterpartyCap = 3;
  let collusionClusterThreshold = 0.8;
  for (const row of rows) {
    const logic = parseAuraState(row.rule_logic);
    const capValue = Number(logic.per_counterparty_cap);
    if (Number.isFinite(capValue) && capValue > 0) {
      perCounterpartyCap = Math.max(perCounterpartyCap, Math.floor(capValue));
    }
    const thresholdValue = Number(logic.collusion_cluster_threshold);
    if (Number.isFinite(thresholdValue) && thresholdValue > 0 && thresholdValue <= 1) {
      collusionClusterThreshold = Math.min(collusionClusterThreshold, thresholdValue);
    }
  }
  return { perCounterpartyCap, collusionClusterThreshold };
};

const diversifyByAuthor = <T extends { authorHash: string }>(items: T[], limit: number): T[] => {
  const buckets = new Map<string, T[]>();
  const order: string[] = [];
  for (const item of items) {
    if (!buckets.has(item.authorHash)) {
      buckets.set(item.authorHash, []);
      order.push(item.authorHash);
    }
    buckets.get(item.authorHash)?.push(item);
  }
  const selected: T[] = [];
  while (selected.length < limit) {
    let progressed = false;
    for (const authorHash of order) {
      const bucket = buckets.get(authorHash);
      if (!bucket || bucket.length === 0) continue;
      selected.push(bucket.shift() as T);
      progressed = true;
      if (selected.length >= limit) break;
    }
    if (!progressed) break;
  }
  return selected;
};

const loadTrustProfiles = async (input: {
  authorHashes: string[];
  viewerDidHash: string | null;
  spaceId?: string;
}) => {
  const db = await getDb();
  const authorHashes = input.authorHashes;
  const profiles = new Map<
    string,
    {
      socialTier: string;
      spaceTier: string | null;
      diversity: number;
      verified: boolean;
      moderated: boolean;
      sharedSpaces: string[];
    }
  >();
  if (authorHashes.length === 0) return profiles;

  const socialAuraRows = (await db("aura_state")
    .whereIn("subject_did_hash", authorHashes)
    .andWhere({ domain: "social" })
    .select("subject_did_hash", "state")) as Array<{ subject_did_hash: string; state: unknown }>;
  const spaceDomain = input.spaceId ? `space:${input.spaceId}` : null;
  const spaceAuraRows = spaceDomain
    ? ((await db("aura_state")
        .whereIn("subject_did_hash", authorHashes)
        .andWhere({ domain: spaceDomain })
        .select("subject_did_hash", "state")) as Array<{
        subject_did_hash: string;
        state: unknown;
      }>)
    : [];
  const socialTierByAuthor = new Map<string, string>();
  const spaceTierByAuthor = new Map<string, string>();
  const diversityByAuthor = new Map<string, number>();
  for (const row of socialAuraRows) {
    const state = parseAuraState(row.state);
    socialTierByAuthor.set(row.subject_did_hash, normalizeTier(state.tier));
    diversityByAuthor.set(row.subject_did_hash, Number(state.diversity ?? 0));
  }
  for (const row of spaceAuraRows) {
    const state = parseAuraState(row.state);
    spaceTierByAuthor.set(row.subject_did_hash, normalizeTier(state.tier));
  }

  const verifiedRows = (await db("issuance_events")
    .whereIn("subject_did_hash", authorHashes)
    .andWhere({ vct: "cuncta.social.account_active" })
    .select("subject_did_hash")
    .groupBy("subject_did_hash")) as Array<{ subject_did_hash: string }>;
  const verifiedSet = new Set(verifiedRows.map((row) => row.subject_did_hash));
  const moderationRows = (await db("social_space_member_restrictions")
    .whereIn("subject_did_hash", authorHashes)
    .select("subject_did_hash")
    .groupBy("subject_did_hash")) as Array<{ subject_did_hash: string }>;
  const moderatedSet = new Set(moderationRows.map((row) => row.subject_did_hash));

  const sharedSpacesByAuthor = new Map<string, string[]>();
  if (input.viewerDidHash) {
    let viewerSpacesQuery = db("social_space_memberships")
      .where({ subject_did_hash: input.viewerDidHash, status: "ACTIVE" })
      .select("space_id");
    if (input.spaceId) {
      viewerSpacesQuery = viewerSpacesQuery.andWhere({ space_id: input.spaceId });
    }
    const viewerSpaces = (await viewerSpacesQuery) as Array<{ space_id: string }>;
    const viewerSpaceIds = viewerSpaces.map((row) => row.space_id);
    if (viewerSpaceIds.length > 0) {
      const sharedRows = (await db("social_space_memberships")
        .whereIn("space_id", viewerSpaceIds)
        .andWhere({ status: "ACTIVE" })
        .whereIn("subject_did_hash", authorHashes)
        .select("subject_did_hash", "space_id")) as Array<{
        subject_did_hash: string;
        space_id: string;
      }>;
      for (const row of sharedRows) {
        const bucket = sharedSpacesByAuthor.get(row.subject_did_hash) ?? [];
        if (!bucket.includes(row.space_id)) {
          bucket.push(row.space_id);
        }
        sharedSpacesByAuthor.set(row.subject_did_hash, bucket);
      }
    }
  }

  for (const authorHash of authorHashes) {
    profiles.set(authorHash, {
      socialTier: socialTierByAuthor.get(authorHash) ?? "bronze",
      spaceTier: spaceTierByAuthor.get(authorHash) ?? null,
      diversity: diversityByAuthor.get(authorHash) ?? 0,
      verified: verifiedSet.has(authorHash),
      moderated: moderatedSet.has(authorHash),
      sharedSpaces: sharedSpacesByAuthor.get(authorHash) ?? []
    });
  }
  return profiles;
};

const tierLabel = (tier: string) => {
  if (tier === "gold") return "Trusted Creator";
  if (tier === "silver") return "Verified Creator";
  return "Verified Account";
};

export const registerSocialRoutes = (app: FastifyInstance) => {
  app.post("/v1/social/profile/create", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = profileSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    let gate: Awaited<ReturnType<typeof verifyAndGate>>;
    try {
      gate = await verifyAndGate({
        subjectDidHash,
        actionId: "social.profile.create",
        actionType: "profile_create",
        presentation: body.presentation,
        nonce: body.nonce,
        audience: body.audience
      });
    } catch {
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);

    const profileId = randomUUID();
    const now = new Date().toISOString();
    const handleHash = hashHex(body.handle.toLowerCase());
    const db = await getDb();
    await db("social_profiles")
      .insert({
        profile_id: profileId,
        subject_did_hash: subjectDidHash,
        handle_hash: handleHash,
        handle: body.handle.toLowerCase(),
        display_name: body.displayName ?? body.handle,
        bio: body.bio ?? null,
        created_at: now,
        updated_at: now
      })
      .onConflict("subject_did_hash")
      .merge({
        handle_hash: handleHash,
        handle: body.handle.toLowerCase(),
        display_name: body.displayName ?? body.handle,
        bio: body.bio ?? null,
        deleted_at: null,
        updated_at: now
      });
    await logAction({
      subjectDidHash,
      actionType: "social.profile.create",
      decision: "ALLOW",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    incCompleted("profile_create");
    await logAction({
      subjectDidHash,
      actionType: "social.profile.create",
      decision: "COMPLETE",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    return reply.send({ decision: "ALLOW", profileId });
  });

  app.post("/v1/social/post", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = postSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    let gate: Awaited<ReturnType<typeof verifyAndGate>>;
    try {
      gate = await verifyAndGate({
        subjectDidHash,
        actionId: "social.post.create",
        actionType: "post",
        presentation: body.presentation,
        nonce: body.nonce,
        audience: body.audience
      });
    } catch {
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);

    const postId = randomUUID();
    const now = new Date().toISOString();
    await (
      await getDb()
    )("social_posts").insert({
      post_id: postId,
      author_subject_did_hash: subjectDidHash,
      content_text: body.content,
      content_hash: hashHex(body.content),
      created_at: now
    });
    await logAction({
      subjectDidHash,
      actionType: "social.post.create",
      decision: "ALLOW",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    incCompleted("post");
    await logAction({
      subjectDidHash,
      actionType: "social.post.create",
      decision: "COMPLETE",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    return reply.send({ decision: "ALLOW", postId });
  });

  app.post("/v1/social/reply", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = replySchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const db = await getDb();
    const parentPost = await db("social_posts")
      .where({ post_id: body.postId })
      .whereNull("deleted_at")
      .first();
    if (!parentPost) {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Target post not found."));
    }
    let gate: Awaited<ReturnType<typeof verifyAndGate>>;
    try {
      gate = await verifyAndGate({
        subjectDidHash,
        actionId: "social.reply.create",
        actionType: "reply",
        presentation: body.presentation,
        nonce: body.nonce,
        audience: body.audience
      });
    } catch {
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);

    const replyId = randomUUID();
    const now = new Date().toISOString();
    await db("social_replies").insert({
      reply_id: replyId,
      post_id: body.postId,
      author_subject_did_hash: subjectDidHash,
      content_text: body.content,
      content_hash: hashHex(body.content),
      created_at: now
    });
    await logAction({
      subjectDidHash,
      actionType: "social.reply.create",
      decision: "ALLOW",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    incCompleted("reply");
    await logAction({
      subjectDidHash,
      actionType: "social.reply.create",
      decision: "COMPLETE",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    return reply.send({ decision: "ALLOW", replyId });
  });

  app.post("/v1/social/follow", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = followSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const followeeHash = pseudonymizer.didToHash(body.followeeDid);
    if (subjectDidHash === followeeHash) {
      return reply.code(400).send(makeErrorResponse("invalid_request", "Cannot follow yourself."));
    }
    let gate: Awaited<ReturnType<typeof verifyAndGate>>;
    try {
      gate = await verifyAndGate({
        subjectDidHash,
        actionId: "social.follow.create",
        actionType: "follow",
        presentation: body.presentation,
        nonce: body.nonce,
        audience: body.audience
      });
    } catch {
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);

    await (
      await getDb()
    )("social_follows")
      .insert({
        follower_subject_did_hash: subjectDidHash,
        followee_subject_did_hash: followeeHash,
        created_at: new Date().toISOString()
      })
      .onConflict(["follower_subject_did_hash", "followee_subject_did_hash"])
      .ignore();
    await logAction({
      subjectDidHash,
      actionType: "social.follow.create",
      decision: "ALLOW",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    incCompleted("follow");
    await logAction({
      subjectDidHash,
      actionType: "social.follow.create",
      decision: "COMPLETE",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    return reply.send({ decision: "ALLOW" });
  });

  app.post("/v1/social/report", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = reportSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    let gate: Awaited<ReturnType<typeof verifyAndGate>>;
    try {
      gate = await verifyAndGate({
        subjectDidHash,
        actionId: "social.report.create",
        actionType: "report",
        presentation: body.presentation,
        nonce: body.nonce,
        audience: body.audience
      });
    } catch {
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const reportId = randomUUID();
    const db = await getDb();
    const now = new Date().toISOString();
    let resolvedSpaceId = body.spaceId ?? null;
    if (!resolvedSpaceId && body.targetSpacePostId) {
      const targetSpacePost = await db("social_space_posts")
        .where({ space_post_id: body.targetSpacePostId })
        .select("space_id")
        .first();
      resolvedSpaceId = (targetSpacePost?.space_id as string | undefined) ?? null;
    }
    await db("social_reports").insert({
      report_id: reportId,
      reporter_subject_did_hash: subjectDidHash,
      target_post_id: body.targetPostId ?? null,
      target_reply_id: body.targetReplyId ?? null,
      space_id: resolvedSpaceId,
      target_space_post_id: body.targetSpacePostId ?? null,
      reason_code: body.reasonCode,
      created_at: now
    });
    if (resolvedSpaceId) {
      await db("social_space_moderation_cases")
        .insert({
          case_id: randomUUID(),
          space_id: resolvedSpaceId,
          report_id: reportId,
          status: "OPEN",
          created_at: now,
          updated_at: now
        })
        .onConflict("report_id")
        .ignore();
    }
    // Moderation hook stub: hash-only signal for internal moderation worker.
    log.info("social.report.moderation_hook_stub", {
      reportId,
      targetPostId: body.targetPostId ?? null,
      targetReplyId: body.targetReplyId ?? null
    });
    await logAction({
      subjectDidHash,
      actionType: "social.report.create",
      decision: "ALLOW",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    incCompleted("report");
    await logAction({
      subjectDidHash,
      actionType: "social.report.create",
      decision: "COMPLETE",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    return reply.send({ decision: "ALLOW", reportId });
  });

  app.post("/v1/social/space/create", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = spaceCreateSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const policyPack = await getSpacePolicyPack(body.policyPackId);
    if (!policyPack) {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Policy pack not found"));
    }
    let gate: Awaited<ReturnType<typeof verifyAndGate>>;
    try {
      gate = await verifyAndGate({
        subjectDidHash,
        actionId: "social.space.create",
        actionType: "space_create",
        presentation: body.presentation,
        nonce: body.nonce,
        audience: body.audience
      });
    } catch {
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);

    const db = await getDb();
    const existing = await db("social_spaces")
      .where({ slug: body.slug })
      .whereNull("archived_at")
      .first();
    if (existing) {
      return reply.code(409).send(makeErrorResponse("invalid_request", "Slug already exists"));
    }
    const now = new Date().toISOString();
    const spaceId = randomUUID();
    await db.transaction(async (trx) => {
      await trx("social_spaces").insert({
        space_id: spaceId,
        slug: body.slug,
        display_name: body.displayName,
        description: body.description ?? null,
        created_by_subject_did_hash: subjectDidHash,
        policy_pack_id: policyPack.policy_pack_id,
        created_at: now
      });
      await trx("social_space_memberships")
        .insert({
          space_id: spaceId,
          subject_did_hash: subjectDidHash,
          status: "ACTIVE",
          joined_at: now
        })
        .onConflict(["space_id", "subject_did_hash"])
        .merge({ status: "ACTIVE", left_at: null, joined_at: now });
    });
    await logAction({
      subjectDidHash,
      actionType: "social.space.create",
      decision: "ALLOW",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    incCompleted("space_create");
    await logAction({
      subjectDidHash,
      actionType: "social.space.create",
      decision: "COMPLETE",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    return reply.send({
      decision: "ALLOW",
      spaceId,
      slug: body.slug,
      policyPackId: policyPack.policy_pack_id
    });
  });

  app.post("/v1/social/space/join", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = spaceJoinSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const space = await getSpaceById(body.spaceId);
    if (!space) {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Space not found"));
    }
    const policyPack = await getSpacePolicyPack(space.policy_pack_id);
    if (!policyPack) {
      return reply
        .code(409)
        .send(makeErrorResponse("invalid_request", "Space policy pack unavailable"));
    }

    let gate: Awaited<ReturnType<typeof verifyAndGate>>;
    try {
      gate = await verifyAndGate({
        subjectDidHash,
        actionId: policyPack.join_action_id,
        actionType: "space_join",
        presentation: body.presentation,
        nonce: body.nonce,
        audience: body.audience,
        pinnedPolicyHash: policyPack.pinned_policy_hash_join ?? policyPack.join_policy_hash ?? null,
        context: { space_id: body.spaceId }
      });
    } catch {
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);

    const now = new Date().toISOString();
    await (
      await getDb()
    )("social_space_memberships")
      .insert({
        space_id: body.spaceId,
        subject_did_hash: subjectDidHash,
        status: "ACTIVE",
        joined_at: now
      })
      .onConflict(["space_id", "subject_did_hash"])
      .merge({ status: "ACTIVE", left_at: null, joined_at: now });
    await logAction({
      subjectDidHash,
      actionType: "social.space.join",
      decision: "ALLOW",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    incCompleted("space_join");
    await logAction({
      subjectDidHash,
      actionType: "social.space.join",
      decision: "COMPLETE",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    await (
      await getDb()
    )("aura_signals")
      .insert({
        subject_did_hash: subjectDidHash,
        domain: `space:${body.spaceId}`,
        signal: "social.space.join_success",
        weight: 1,
        counterparty_did_hash: null,
        event_hash: hashCanonicalJson({
          signal: "social.space.join_success",
          subjectDidHash,
          spaceId: body.spaceId,
          createdAt: now
        }),
        created_at: now
      })
      .onConflict("event_hash")
      .ignore();
    return reply.send({ decision: "ALLOW", spaceId: body.spaceId });
  });

  app.post("/v1/social/space/post", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = spacePostSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const space = await getSpaceById(body.spaceId);
    if (!space) {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Space not found"));
    }
    const policyPack = await getSpacePolicyPack(space.policy_pack_id);
    if (!policyPack) {
      return reply
        .code(409)
        .send(makeErrorResponse("invalid_request", "Space policy pack unavailable"));
    }
    const restrictedInSpace = await isSpaceMemberRestricted(body.spaceId, subjectDidHash);
    if (restrictedInSpace) {
      return reply.code(403).send(
        makeErrorResponse("invalid_request", "This member is restricted in the target space.", {
          devMode: config.DEV_MODE
        })
      );
    }
    const membership = await (await getDb())("social_space_memberships")
      .where({ space_id: body.spaceId, subject_did_hash: subjectDidHash, status: "ACTIVE" })
      .first();
    if (!membership) {
      return reply.code(403).send(
        makeErrorResponse("invalid_request", "Join the space before posting.", {
          devMode: config.DEV_MODE
        })
      );
    }

    let gate: Awaited<ReturnType<typeof verifyAndGate>>;
    try {
      gate = await verifyAndGate({
        subjectDidHash,
        actionId: policyPack.post_action_id,
        actionType: "space_post",
        presentation: body.presentation,
        nonce: body.nonce,
        audience: body.audience,
        pinnedPolicyHash: policyPack.pinned_policy_hash_post ?? policyPack.post_policy_hash ?? null,
        context: { space_id: body.spaceId }
      });
    } catch {
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);

    const now = new Date().toISOString();
    const spacePostId = randomUUID();
    await (
      await getDb()
    )("social_space_posts").insert({
      space_post_id: spacePostId,
      space_id: body.spaceId,
      author_subject_did_hash: subjectDidHash,
      content_text: body.content,
      content_hash: hashHex(body.content),
      created_at: now
    });
    await logAction({
      subjectDidHash,
      actionType: "social.space.post.create",
      decision: "ALLOW",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    incCompleted("space_post");
    await logAction({
      subjectDidHash,
      actionType: "social.space.post.create",
      decision: "COMPLETE",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    await (
      await getDb()
    )("aura_signals")
      .insert({
        subject_did_hash: subjectDidHash,
        domain: `space:${body.spaceId}`,
        signal: "social.space.post_success",
        weight: 1,
        counterparty_did_hash: null,
        event_hash: hashCanonicalJson({
          signal: "social.space.post_success",
          subjectDidHash,
          spaceId: body.spaceId,
          postId: spacePostId,
          createdAt: now
        }),
        created_at: now
      })
      .onConflict("event_hash")
      .ignore();
    return reply.send({ decision: "ALLOW", spacePostId });
  });

  app.post("/v1/social/space/moderate", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = spaceModerateSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const space = await getSpaceById(body.spaceId);
    if (!space) {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Space not found"));
    }
    const policyPack = await getSpacePolicyPack(space.policy_pack_id);
    if (!policyPack) {
      return reply
        .code(409)
        .send(makeErrorResponse("invalid_request", "Space policy pack unavailable"));
    }

    let gate: Awaited<ReturnType<typeof verifyAndGate>>;
    try {
      gate = await verifyAndGate({
        subjectDidHash,
        actionId: policyPack.moderate_action_id,
        actionType: "space_moderate",
        presentation: body.presentation,
        nonce: body.nonce,
        audience: body.audience,
        pinnedPolicyHash:
          policyPack.pinned_policy_hash_moderate ?? policyPack.moderate_policy_hash ?? null,
        context: { space_id: body.spaceId }
      });
    } catch {
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);

    if (body.operation === "remove_content" && !body.targetSpacePostId) {
      return reply
        .code(400)
        .send(makeErrorResponse("invalid_request", "targetSpacePostId is required"));
    }
    if (body.operation === "restrict_member" && !body.targetSubjectDid) {
      return reply
        .code(400)
        .send(makeErrorResponse("invalid_request", "targetSubjectDid is required"));
    }

    const db = await getDb();
    const now = new Date().toISOString();
    const moderationId = randomUUID();
    const targetSubjectDidHash = body.targetSubjectDid
      ? pseudonymizer.didToHash(body.targetSubjectDid)
      : null;
    const auditHash = hashCanonicalJson({
      moderationId,
      spaceId: body.spaceId,
      moderator: subjectDidHash,
      operation: body.operation,
      targetSpacePostId: body.targetSpacePostId ?? null,
      targetSubjectDidHash,
      reasonCode: body.reasonCode,
      createdAt: now
    });

    await db.transaction(async (trx) => {
      if (body.operation === "remove_content" && body.targetSpacePostId) {
        await trx("social_space_posts")
          .where({ space_post_id: body.targetSpacePostId, space_id: body.spaceId })
          .whereNull("deleted_at")
          .update({ deleted_at: now, content_text: "[removed by moderation]" });
      }
      if (body.operation === "restrict_member" && targetSubjectDidHash) {
        await trx("social_space_member_restrictions")
          .insert({
            space_id: body.spaceId,
            subject_did_hash: targetSubjectDidHash,
            reason_code: body.reasonCode,
            restricted_at: now
          })
          .onConflict(["space_id", "subject_did_hash"])
          .merge({ reason_code: body.reasonCode, restricted_at: now });
      }
      await trx("social_space_moderation_actions").insert({
        moderation_id: moderationId,
        space_id: body.spaceId,
        moderator_subject_did_hash: subjectDidHash,
        target_subject_did_hash: targetSubjectDidHash,
        target_space_post_id: body.targetSpacePostId ?? null,
        operation: body.operation,
        reason_code: body.reasonCode,
        audit_hash: auditHash,
        anchor_requested: body.anchor ?? false,
        created_at: now
      });
      if (body.anchor && config.ANCHOR_AUTH_SECRET) {
        await trx("anchor_outbox")
          .insert({
            outbox_id: randomUUID(),
            event_type: "SOCIAL_SPACE_MODERATION",
            payload_hash: auditHash,
            payload_meta: {
              action: "social.space.moderate",
              operation: body.operation,
              space_id_hash: hashHex(body.spaceId),
              moderator_subject_did_hash: subjectDidHash,
              ...signAnchorMeta(config.ANCHOR_AUTH_SECRET, {
                payloadHash: auditHash,
                eventType: "SOCIAL_SPACE_MODERATION"
              })
            },
            status: "PENDING",
            attempts: 0,
            next_retry_at: now,
            created_at: now,
            updated_at: now
          })
          .onConflict("payload_hash")
          .ignore();
      }
    });

    await logAction({
      subjectDidHash,
      actionType: "social.space.moderate",
      decision: "ALLOW",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    incCompleted("space_moderate");
    await logAction({
      subjectDidHash,
      actionType: "social.space.moderate",
      decision: "COMPLETE",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    return reply.send({
      decision: "ALLOW",
      moderationId,
      auditHash,
      anchored: Boolean(body.anchor)
    });
  });

  app.get("/v1/social/space/feed", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const query = spaceFeedQuerySchema.parse(request.query ?? {});
    const space = await getSpaceById(query.spaceId);
    if (!space) {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Space not found"));
    }
    const policyPack = await getSpacePolicyPack(space.policy_pack_id);
    const db = await getDb();
    const rows = await db("social_space_posts")
      .where({ space_id: query.spaceId })
      .whereNull("deleted_at")
      .orderBy("created_at", "desc")
      .limit(query.limit);
    const privacyCache = new Map<string, PrivacyStatus>();
    const posts: Array<Record<string, unknown>> = [];
    for (const row of rows) {
      const authorHash = String(row.author_subject_did_hash);
      let privacy = privacyCache.get(authorHash);
      if (!privacy) {
        privacy = await getPrivacyStatus(authorHash).catch(() => ({
          restricted: false,
          tombstoned: false
        }));
        privacyCache.set(authorHash, privacy);
      }
      if (privacy.tombstoned || privacy.restricted) {
        continue;
      }
      posts.push({
        space_post_id: row.space_post_id,
        content_text: row.content_text,
        content_hash: row.content_hash,
        created_at: row.created_at,
        trust_stamps: ["Space Poster"]
      });
    }
    return reply.send({
      space: {
        space_id: space.space_id,
        slug: space.slug,
        display_name: space.display_name,
        policy_pack_id: space.policy_pack_id,
        visibility: policyPack?.visibility ?? "members"
      },
      posts
    });
  });

  app.get("/v1/social/space/flow", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    metrics.incCounter("social_space_flow_requests_total");
    const query = spaceFlowQuerySchema.parse(request.query ?? {});
    if (query.trust) {
      metrics.incCounter("social_space_trust_lens_usage_total", { mode: query.trust });
    }
    if (query.safety === "strict") {
      metrics.incCounter("social_space_trust_lens_usage_total", { mode: "safety_strict" });
    }
    if (query.trust === "space_members" && !query.viewerDid) {
      return reply
        .code(400)
        .send(
          makeErrorResponse("invalid_request", "viewerDid is required for trust=space_members")
        );
    }

    const space = await getSpaceById(query.spaceId);
    if (!space) {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Space not found"));
    }
    const policyPack = await getSpacePolicyPack(space.policy_pack_id);
    if (!policyPack) {
      return reply
        .code(409)
        .send(makeErrorResponse("invalid_request", "Space policy pack unavailable"));
    }
    const postRequirements = await getActionRequirementSummary(policyPack.post_action_id, {
      space_id: query.spaceId
    }).catch(() => []);
    const baselineFloor = inferFloorTierFromRequirements(postRequirements);
    const minTier = getSpaceFlowThresholdTier(query.safety === "strict", baselineFloor);
    const minTierRank = tierRank[minTier] ?? 0;
    const antiGaming = await getFlowAntiGaming();
    const maxPerAuthor = Math.max(2, Math.min(6, antiGaming.perCounterpartyCap));

    const db = await getDb();
    const rows = await db("social_space_posts")
      .where({ space_id: query.spaceId })
      .whereNull("deleted_at")
      .orderBy("created_at", "desc")
      .limit(Math.max(query.limit * 8, 60));
    if (!rows.length) {
      return reply.send({
        mode: "space_flow",
        trust: query.trust ?? null,
        safety: query.safety ?? "default",
        space: {
          space_id: space.space_id,
          slug: space.slug,
          display_name: space.display_name
        },
        posts: []
      });
    }

    const viewerDidHash = query.viewerDid ? pseudonymizer.didToHash(query.viewerDid) : null;
    const authorHashes = Array.from(
      new Set(rows.map((row) => String(row.author_subject_did_hash)))
    );
    const profiles = await loadTrustProfiles({
      authorHashes,
      viewerDidHash,
      spaceId: query.spaceId
    });
    const privacyCache = new Map<string, PrivacyStatus>();
    await Promise.all(
      authorHashes.map(async (authorHash) => {
        const privacy = await getPrivacyStatus(authorHash).catch(() => ({
          restricted: false,
          tombstoned: false
        }));
        privacyCache.set(authorHash, privacy);
      })
    );
    const selectedPerAuthor = new Map<string, number>();
    const staged = rows
      .map((row) => {
        const authorHash = String(row.author_subject_did_hash);
        const profile = profiles.get(authorHash);
        const tier = profile?.spaceTier ?? profile?.socialTier ?? "bronze";
        return {
          row,
          authorHash,
          profile,
          tier,
          createdAt: Date.parse(String(row.created_at))
        };
      })
      .sort((a, b) => {
        if (b.createdAt !== a.createdAt) return b.createdAt - a.createdAt;
        const tierDelta = (tierRank[b.tier] ?? 0) - (tierRank[a.tier] ?? 0);
        if (tierDelta !== 0) return tierDelta;
        return (b.profile?.diversity ?? 0) - (a.profile?.diversity ?? 0);
      });
    const filtered = staged.filter((entry) => {
      const privacy = privacyCache.get(entry.authorHash);
      if (privacy?.restricted || privacy?.tombstoned) return false;
      const profile = entry.profile;
      if (!profile) return false;
      if ((tierRank[entry.tier] ?? 0) < minTierRank) return false;
      if (antiGaming.collusionClusterThreshold <= 0.8 && profile.diversity < 1) return false;
      const seen = selectedPerAuthor.get(entry.authorHash) ?? 0;
      if (seen >= maxPerAuthor) return false;
      if (query.trust === "verified_only") {
        if (!profile.verified || profile.moderated) return false;
      }
      if (query.trust === "trusted_creator" && (tierRank[entry.tier] ?? 0) < tierRank.silver) {
        return false;
      }
      if (query.trust === "space_members" && profile.sharedSpaces.length === 0) {
        return false;
      }
      selectedPerAuthor.set(entry.authorHash, seen + 1);
      return true;
    });
    const diversified = diversifyByAuthor(filtered, query.limit);
    const posts = diversified.map((entry) => ({
      space_post_id: entry.row.space_post_id,
      content_text: entry.row.content_text,
      content_hash: entry.row.content_hash,
      created_at: entry.row.created_at,
      trust_stamps: [tierLabel(entry.tier)],
      explain_available: true
    }));
    return reply.send({
      mode: "space_flow",
      trust: query.trust ?? null,
      safety: query.safety ?? "default",
      space: {
        space_id: space.space_id,
        slug: space.slug,
        display_name: space.display_name
      },
      posts
    });
  });

  app.get("/v1/social/spaces", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const query = spacesQuerySchema.parse(request.query ?? {});
    const db = await getDb();
    let queryBuilder = db("social_spaces")
      .whereNull("archived_at")
      .orderBy("created_at", "desc")
      .limit(query.limit);
    if (query.search) {
      queryBuilder = queryBuilder.where((builder) => {
        builder
          .whereILike("slug", `%${query.search}%`)
          .orWhereILike("display_name", `%${query.search}%`)
          .orWhereILike("description", `%${query.search}%`);
      });
    }
    const rows = (await queryBuilder.select(
      "space_id",
      "slug",
      "display_name",
      "description",
      "policy_pack_id"
    )) as Array<{
      space_id: string;
      slug: string;
      display_name: string;
      description?: string | null;
      policy_pack_id: string;
    }>;
    const spaces = await Promise.all(
      rows.map(async (row) => {
        const policyPack = await getSpacePolicyPack(row.policy_pack_id);
        const postRequirements = policyPack
          ? await getActionRequirementSummary(policyPack.post_action_id, {
              space_id: row.space_id
            }).catch(() => [])
          : [];
        return {
          space_id: row.space_id,
          slug: row.slug,
          name: row.display_name,
          description: row.description ?? "",
          member_count: await getSpaceMemberCount(row.space_id),
          posting_requirement_summary: summarizeRequirementLabels(postRequirements)
        };
      })
    );
    return reply.send({ spaces });
  });

  app.get("/v1/social/spaces/:spaceId", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const { spaceId } = spaceParamsSchema.parse(request.params ?? {});
    const space = await getSpaceById(spaceId);
    if (!space) {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Space not found"));
    }
    const policyPack = await getSpacePolicyPack(space.policy_pack_id);
    if (!policyPack) {
      return reply
        .code(409)
        .send(makeErrorResponse("invalid_request", "Space policy pack unavailable"));
    }
    const joinRequirements = await getActionRequirementSummary(policyPack.join_action_id, {
      space_id: spaceId
    }).catch(() => []);
    const postRequirements = await getActionRequirementSummary(policyPack.post_action_id, {
      space_id: spaceId
    }).catch(() => []);
    const moderateRequirements = await getActionRequirementSummary(policyPack.moderate_action_id, {
      space_id: spaceId
    }).catch(() => []);
    return reply.send({
      space: {
        space_id: space.space_id,
        slug: space.slug,
        name: space.display_name,
        description: space.description ?? "",
        member_count: await getSpaceMemberCount(space.space_id),
        created_at: space.created_at
      },
      policy_pack: {
        policy_pack_id: policyPack.policy_pack_id,
        display_name: policyPack.display_name ?? policyPack.policy_pack_id,
        visibility: policyPack.visibility
      },
      requirements_summary: {
        join: joinRequirements,
        post: postRequirements,
        moderate: moderateRequirements
      }
    });
  });

  app.get("/v1/social/spaces/:spaceId/rules", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    metrics.incCounter("social_space_governance_requests_total");
    const { spaceId } = spaceParamsSchema.parse(request.params ?? {});
    const space = await getSpaceById(spaceId);
    if (!space) {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Space not found"));
    }
    const policyPack = await getSpacePolicyPack(space.policy_pack_id);
    if (!policyPack) {
      return reply
        .code(409)
        .send(makeErrorResponse("invalid_request", "Space policy pack unavailable"));
    }
    const joinRequirements = await getActionRequirementSummary(policyPack.join_action_id, {
      space_id: spaceId
    });
    const postRequirements = await getActionRequirementSummary(policyPack.post_action_id, {
      space_id: spaceId
    });
    const moderateRequirements = await getActionRequirementSummary(policyPack.moderate_action_id, {
      space_id: spaceId
    });
    const joinPolicy = await getRequirements(policyPack.join_action_id, {
      space_id: spaceId
    }).catch(() => null);
    const postPolicy = await getRequirements(policyPack.post_action_id, {
      space_id: spaceId
    }).catch(() => null);
    const moderatePolicy = await getRequirements(policyPack.moderate_action_id, {
      space_id: spaceId
    }).catch(() => null);
    return reply.send({
      space_id: spaceId,
      space_slug: space.slug,
      policy_pack: {
        policy_pack_id: policyPack.policy_pack_id,
        display_name: policyPack.display_name ?? policyPack.policy_pack_id,
        visibility: policyPack.visibility
      },
      join_requirements: joinRequirements,
      post_requirements: postRequirements,
      moderation_requirements: moderateRequirements,
      aura_thresholds: {
        join: buildAuraThresholdSummary(joinRequirements),
        post: buildAuraThresholdSummary(postRequirements),
        moderate: buildAuraThresholdSummary(moderateRequirements)
      },
      governance: {
        pack: {
          policy_pack_id: policyPack.policy_pack_id,
          display_name: policyPack.display_name ?? policyPack.policy_pack_id,
          visibility: policyPack.visibility
        },
        policy_versions: {
          join: {
            policy_id: joinPolicy?.policyId ?? null,
            version: joinPolicy?.policyVersion ?? null
          },
          post: {
            policy_id: postPolicy?.policyId ?? null,
            version: postPolicy?.policyVersion ?? null
          },
          moderate: {
            policy_id: moderatePolicy?.policyId ?? null,
            version: moderatePolicy?.policyVersion ?? null
          }
        },
        trust_floor: {
          join: inferFloorTierFromRequirements(joinRequirements),
          post: inferFloorTierFromRequirements(postRequirements),
          moderate: inferFloorTierFromRequirements(moderateRequirements)
        },
        pinning: {
          join: Boolean(policyPack.pinned_policy_hash_join ?? policyPack.join_policy_hash),
          post: Boolean(policyPack.pinned_policy_hash_post ?? policyPack.post_policy_hash),
          moderate: Boolean(
            policyPack.pinned_policy_hash_moderate ?? policyPack.moderate_policy_hash
          )
        }
      }
    });
  });

  app.get("/v1/social/spaces/:spaceId/governance", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    metrics.incCounter("social_space_governance_requests_total");
    const { spaceId } = spaceParamsSchema.parse(request.params ?? {});
    const space = await getSpaceById(spaceId);
    if (!space) {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Space not found"));
    }
    const policyPack = await getSpacePolicyPack(space.policy_pack_id);
    if (!policyPack) {
      return reply
        .code(409)
        .send(makeErrorResponse("invalid_request", "Space policy pack unavailable"));
    }
    const joinRequirements = await getActionRequirementSummary(policyPack.join_action_id, {
      space_id: spaceId
    }).catch(() => []);
    const postRequirements = await getActionRequirementSummary(policyPack.post_action_id, {
      space_id: spaceId
    }).catch(() => []);
    const moderateRequirements = await getActionRequirementSummary(policyPack.moderate_action_id, {
      space_id: spaceId
    }).catch(() => []);
    const joinPolicy = await getRequirements(policyPack.join_action_id, {
      space_id: spaceId
    }).catch(() => null);
    const postPolicy = await getRequirements(policyPack.post_action_id, {
      space_id: spaceId
    }).catch(() => null);
    const moderatePolicy = await getRequirements(policyPack.moderate_action_id, {
      space_id: spaceId
    }).catch(() => null);
    return reply.send({
      space: {
        space_id: space.space_id,
        slug: space.slug,
        display_name: space.display_name
      },
      policy_pack: {
        policy_pack_id: policyPack.policy_pack_id,
        display_name: policyPack.display_name ?? policyPack.policy_pack_id,
        visibility: policyPack.visibility
      },
      policy_versions: {
        join: {
          policy_id: joinPolicy?.policyId ?? null,
          version: joinPolicy?.policyVersion ?? null
        },
        post: {
          policy_id: postPolicy?.policyId ?? null,
          version: postPolicy?.policyVersion ?? null
        },
        moderate: {
          policy_id: moderatePolicy?.policyId ?? null,
          version: moderatePolicy?.policyVersion ?? null
        }
      },
      trust_floor: {
        join: inferFloorTierFromRequirements(joinRequirements),
        post: inferFloorTierFromRequirements(postRequirements),
        moderate: inferFloorTierFromRequirements(moderateRequirements)
      },
      pinning: {
        join: Boolean(policyPack.pinned_policy_hash_join ?? policyPack.join_policy_hash),
        post: Boolean(policyPack.pinned_policy_hash_post ?? policyPack.post_policy_hash),
        moderate: Boolean(policyPack.pinned_policy_hash_moderate ?? policyPack.moderate_policy_hash)
      }
    });
  });

  app.get("/v1/social/spaces/:spaceId/moderation/cases", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const { spaceId } = spaceParamsSchema.parse(request.params ?? {});
    const query = spaceModerationCasesQuerySchema.parse(request.query ?? {});
    const subjectDidHash = pseudonymizer.didToHash(query.subjectDid);
    const space = await getSpaceById(spaceId);
    if (!space) {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Space not found"));
    }
    const policyPack = await getSpacePolicyPack(space.policy_pack_id);
    if (!policyPack) {
      return reply
        .code(409)
        .send(makeErrorResponse("invalid_request", "Space policy pack unavailable"));
    }
    let gate: Awaited<ReturnType<typeof verifyAndGate>>;
    try {
      gate = await verifyAndGate({
        subjectDidHash,
        actionId: policyPack.moderate_action_id,
        actionType: "space_moderate",
        presentation: query.presentation,
        nonce: query.nonce,
        audience: query.audience,
        pinnedPolicyHash:
          policyPack.pinned_policy_hash_moderate ?? policyPack.moderate_policy_hash ?? null,
        context: { space_id: spaceId }
      });
    } catch {
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const db = await getDb();
    const cases = (await db("social_space_moderation_cases")
      .where({ space_id: spaceId })
      .orderBy("created_at", "desc")) as SpaceModerationCaseRecord[];
    await logAction({
      subjectDidHash,
      actionType: "social.space.moderation.cases.list",
      decision: "ALLOW",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    return reply.send({ cases });
  });

  app.post(
    "/v1/social/spaces/:spaceId/moderation/cases/:caseId/resolve",
    async (request, reply) => {
      await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
      if (reply.sent) return;
      const { spaceId, caseId } = moderationCaseParamsSchema.parse(request.params ?? {});
      const body = spaceModerationCaseResolveSchema.parse(request.body ?? {});
      const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
      const space = await getSpaceById(spaceId);
      if (!space) {
        return reply.code(404).send(makeErrorResponse("invalid_request", "Space not found"));
      }
      const policyPack = await getSpacePolicyPack(space.policy_pack_id);
      if (!policyPack) {
        return reply
          .code(409)
          .send(makeErrorResponse("invalid_request", "Space policy pack unavailable"));
      }
      let gate: Awaited<ReturnType<typeof verifyAndGate>>;
      try {
        gate = await verifyAndGate({
          subjectDidHash,
          actionId: policyPack.moderate_action_id,
          actionType: "space_moderate",
          presentation: body.presentation,
          nonce: body.nonce,
          audience: body.audience,
          pinnedPolicyHash:
            policyPack.pinned_policy_hash_moderate ?? policyPack.moderate_policy_hash ?? null,
          context: { space_id: spaceId }
        });
      } catch {
        return reply
          .code(503)
          .send(
            makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
              devMode: config.DEV_MODE
            })
          );
      }
      if (gate.denied) return reply.code(403).send(gate.denied);
      const db = await getDb();
      const existingCase = (await db("social_space_moderation_cases")
        .where({ case_id: caseId, space_id: spaceId })
        .first()) as SpaceModerationCaseRecord | undefined;
      if (!existingCase) {
        return reply
          .code(404)
          .send(makeErrorResponse("invalid_request", "Moderation case not found"));
      }
      const now = new Date().toISOString();
      const auditHash = hashCanonicalJson({
        caseId,
        spaceId,
        resolver: subjectDidHash,
        previousStatus: existingCase.status,
        nextStatus: "RESOLVED",
        resolvedAt: now
      });
      await db.transaction(async (trx) => {
        await trx("social_space_moderation_cases")
          .where({ case_id: caseId, space_id: spaceId })
          .update({ status: "RESOLVED", updated_at: now });
        await trx("social_space_moderation_actions").insert({
          moderation_id: randomUUID(),
          space_id: spaceId,
          moderator_subject_did_hash: subjectDidHash,
          target_subject_did_hash: null,
          target_space_post_id: null,
          operation: "resolve_case",
          reason_code: "case_resolved",
          audit_hash: auditHash,
          anchor_requested: body.anchor ?? false,
          created_at: now
        });
        if (body.anchor && config.ANCHOR_AUTH_SECRET) {
          await trx("anchor_outbox")
            .insert({
              outbox_id: randomUUID(),
              event_type: "SOCIAL_SPACE_MODERATION_CASE",
              payload_hash: auditHash,
              payload_meta: {
                action: "social.space.moderation.case.resolve",
                case_id: caseId,
                space_id_hash: hashHex(spaceId),
                moderator_subject_did_hash: subjectDidHash,
                ...signAnchorMeta(config.ANCHOR_AUTH_SECRET, {
                  payloadHash: auditHash,
                  eventType: "SOCIAL_SPACE_MODERATION_CASE"
                })
              },
              status: "PENDING",
              attempts: 0,
              next_retry_at: now,
              created_at: now,
              updated_at: now
            })
            .onConflict("payload_hash")
            .ignore();
        }
      });
      await logAction({
        subjectDidHash,
        actionType: "social.space.moderation.case.resolve",
        decision: "ALLOW",
        policyId: gate.allowMeta?.policyId,
        policyVersion: gate.allowMeta?.policyVersion
      }).catch(() => undefined);
      return reply.send({ decision: "ALLOW", caseId, status: "RESOLVED" });
    }
  );

  app.get("/v1/social/spaces/:spaceId/moderation/audit", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    metrics.incCounter("social_space_moderation_audit_requests_total");
    const { spaceId } = spaceParamsSchema.parse(request.params ?? {});
    const query = moderationAuditQuerySchema.parse(request.query ?? {});
    const subjectDidHash = pseudonymizer.didToHash(query.subjectDid);
    const space = await getSpaceById(spaceId);
    if (!space) {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Space not found"));
    }
    const policyPack = await getSpacePolicyPack(space.policy_pack_id);
    if (!policyPack) {
      return reply
        .code(409)
        .send(makeErrorResponse("invalid_request", "Space policy pack unavailable"));
    }
    let gate: Awaited<ReturnType<typeof verifyAndGate>>;
    try {
      gate = await verifyAndGate({
        subjectDidHash,
        actionId: policyPack.moderate_action_id,
        actionType: "space_moderate",
        presentation: query.presentation,
        nonce: query.nonce,
        audience: query.audience,
        pinnedPolicyHash:
          policyPack.pinned_policy_hash_moderate ?? policyPack.moderate_policy_hash ?? null,
        context: { space_id: spaceId }
      });
    } catch {
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const db = await getDb();
    const rows = await db("social_space_moderation_actions")
      .where({ space_id: spaceId })
      .orderBy("created_at", "desc")
      .limit(query.limit);
    const actions = rows.map((row) => ({
      moderation_id: row.moderation_id,
      operation: row.operation,
      reason_code: row.reason_code,
      target_space_post_id: row.target_space_post_id,
      audit_hash: row.audit_hash,
      anchor_requested: Boolean(row.anchor_requested),
      created_at: row.created_at
    }));
    return reply.send({ actions });
  });

  app.get("/v1/social/spaces/:spaceId/analytics", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    metrics.incCounter("social_space_analytics_requests_total");
    const { spaceId } = spaceParamsSchema.parse(request.params ?? {});
    const query = spaceAnalyticsQuerySchema.parse(request.query ?? {});
    const space = await getSpaceById(spaceId);
    if (!space) {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Space not found"));
    }
    const db = await getDb();
    const since = new Date(Date.now() - query.limit * 24 * 60 * 60 * 1000).toISOString();
    const memberRows = (await db("social_space_memberships")
      .where({ space_id: spaceId })
      .where("joined_at", ">=", since)
      .select("subject_did_hash")) as Array<{ subject_did_hash: string }>;
    const postRows = (await db("social_space_posts")
      .where({ space_id: spaceId })
      .where("created_at", ">=", since)
      .select("author_subject_did_hash")) as Array<{ author_subject_did_hash: string }>;
    const moderationTotalRow = await db("social_space_moderation_actions")
      .where({ space_id: spaceId })
      .where("created_at", ">=", since)
      .count<{ count: string }>("moderation_id as count")
      .first();
    const authorHashes = Array.from(new Set(postRows.map((row) => row.author_subject_did_hash)));
    const trustProfiles = await loadTrustProfiles({ authorHashes, viewerDidHash: null, spaceId });
    const trustedPostCount = postRows.filter((row) => {
      const profile = trustProfiles.get(row.author_subject_did_hash);
      const effectiveTier = profile?.spaceTier ?? profile?.socialTier ?? "bronze";
      return (tierRank[effectiveTier] ?? 0) >= tierRank.silver;
    }).length;
    const postsTotal = postRows.length;
    const joinsTotal = memberRows.length;
    return reply.send({
      space: { space_id: space.space_id, slug: space.slug, display_name: space.display_name },
      window_days: query.limit,
      trust_converted_actions: {
        joins_total: joinsTotal,
        posts_total: postsTotal,
        posts_trust_qualified: trustedPostCount,
        posts_trust_conversion_rate:
          postsTotal > 0 ? Number((trustedPostCount / postsTotal).toFixed(4)) : 0
      },
      moderation_actions_total: Number(moderationTotalRow?.count ?? 0)
    });
  });

  app.get("/v1/social/feed", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const query = feedQuerySchema.parse(request.query ?? {});
    const db = await getDb();
    const posts = await db("social_posts")
      .whereNull("deleted_at")
      .orderBy("created_at", "desc")
      .limit(query.limit);
    const tombstoneCache = new Map<string, boolean>();
    const postIds: string[] = [];
    const visiblePosts: Array<Record<string, unknown>> = [];
    for (const post of posts) {
      const authorHash = String(post.author_subject_did_hash);
      let tombstoned = tombstoneCache.get(authorHash);
      if (tombstoned === undefined) {
        const privacy = await getPrivacyStatus(authorHash).catch(() => ({
          restricted: false,
          tombstoned: false
        }));
        tombstoned = privacy.tombstoned;
        tombstoneCache.set(authorHash, tombstoned);
      }
      if (tombstoned) {
        await purgeSubjectDataOnTombstone(authorHash).catch(() => undefined);
        continue;
      }
      postIds.push(String(post.post_id));
      visiblePosts.push({
        post_id: post.post_id,
        content_text: post.content_text,
        content_hash: post.content_hash,
        created_at: post.created_at,
        replies: []
      });
    }
    const replies = postIds.length
      ? await db("social_replies")
          .whereIn("post_id", postIds)
          .whereNull("deleted_at")
          .orderBy("created_at", "asc")
      : [];
    const byPost = new Map<string, Array<Record<string, unknown>>>();
    for (const entry of replies) {
      const authorHash = String(entry.author_subject_did_hash);
      let tombstoned = tombstoneCache.get(authorHash);
      if (tombstoned === undefined) {
        const privacy = await getPrivacyStatus(authorHash).catch(() => ({
          restricted: false,
          tombstoned: false
        }));
        tombstoned = privacy.tombstoned;
        tombstoneCache.set(authorHash, tombstoned);
      }
      if (tombstoned) {
        await purgeSubjectDataOnTombstone(authorHash).catch(() => undefined);
        continue;
      }
      const bucket = byPost.get(String(entry.post_id)) ?? [];
      bucket.push({
        reply_id: entry.reply_id,
        content_text: entry.content_text,
        content_hash: entry.content_hash,
        created_at: entry.created_at
      });
      byPost.set(String(entry.post_id), bucket);
    }
    for (const post of visiblePosts) {
      post.replies = byPost.get(String(post.post_id)) ?? [];
    }
    return reply.send({ posts: visiblePosts });
  });

  app.get("/v1/social/feed/flow", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    metrics.incCounter("social_flow_feed_requests_total");
    const query = flowFeedQuerySchema.parse(request.query ?? {});
    if (query.trust) {
      metrics.incCounter("social_trust_lens_usage_total", { mode: query.trust });
    }
    if (query.safety === "strict") {
      metrics.incCounter("social_trust_lens_usage_total", { mode: "safety_strict" });
    }

    if (query.trust === "space_members" && !query.viewerDid) {
      return reply
        .code(400)
        .send(
          makeErrorResponse("invalid_request", "viewerDid is required for trust=space_members")
        );
    }

    const db = await getDb();
    const candidateRows = await db("social_posts")
      .whereNull("deleted_at")
      .orderBy("created_at", "desc")
      .limit(Math.max(query.limit * 8, 60));
    if (!candidateRows.length) return reply.send({ mode: "flow", posts: [] });

    const viewerDidHash = query.viewerDid ? pseudonymizer.didToHash(query.viewerDid) : null;
    const authorHashes = Array.from(
      new Set(
        candidateRows
          .map((row) => String(row.author_subject_did_hash))
          .filter((value) => value.length > 0)
      )
    );
    const privacyCache = new Map<string, PrivacyStatus>();
    await Promise.all(
      authorHashes.map(async (authorHash) => {
        const privacy = await getPrivacyStatus(authorHash).catch(() => ({
          restricted: false,
          tombstoned: false
        }));
        privacyCache.set(authorHash, privacy);
      })
    );

    const auraRows = (await db("aura_state")
      .whereIn("subject_did_hash", authorHashes)
      .andWhere({ domain: "social" })
      .select("subject_did_hash", "state")) as Array<{ subject_did_hash: string; state: unknown }>;
    const tierByAuthor = new Map<string, string>();
    const diversityByAuthor = new Map<string, number>();
    for (const row of auraRows) {
      const state = parseAuraState(row.state);
      tierByAuthor.set(row.subject_did_hash, normalizeTier(state.tier));
      diversityByAuthor.set(row.subject_did_hash, Number(state.diversity ?? 0));
    }

    const verifiedRows = (await db("issuance_events")
      .whereIn("subject_did_hash", authorHashes)
      .andWhere({ vct: "cuncta.social.account_active" })
      .select("subject_did_hash")
      .groupBy("subject_did_hash")) as Array<{ subject_did_hash: string }>;
    const verifiedAuthorSet = new Set(verifiedRows.map((row) => row.subject_did_hash));

    const moderationRows = (await db("social_space_member_restrictions")
      .whereIn("subject_did_hash", authorHashes)
      .select("subject_did_hash")
      .groupBy("subject_did_hash")) as Array<{ subject_did_hash: string }>;
    const moderatedAuthorSet = new Set(moderationRows.map((row) => row.subject_did_hash));

    const sharedSpacesByAuthor = new Map<string, string[]>();
    if (viewerDidHash) {
      const viewerSpaces = (await db("social_space_memberships")
        .where({ subject_did_hash: viewerDidHash, status: "ACTIVE" })
        .select("space_id")) as Array<{ space_id: string }>;
      const viewerSpaceIds = viewerSpaces.map((row) => row.space_id);
      if (viewerSpaceIds.length > 0) {
        const sharedRows = (await db("social_space_memberships")
          .whereIn("space_id", viewerSpaceIds)
          .andWhere({ status: "ACTIVE" })
          .whereIn("subject_did_hash", authorHashes)
          .select("subject_did_hash", "space_id")) as Array<{
          subject_did_hash: string;
          space_id: string;
        }>;
        for (const row of sharedRows) {
          const bucket = sharedSpacesByAuthor.get(row.subject_did_hash) ?? [];
          if (!bucket.includes(row.space_id)) {
            bucket.push(row.space_id);
          }
          sharedSpacesByAuthor.set(row.subject_did_hash, bucket);
        }
      }
    }

    const antiGaming = await getFlowAntiGaming();
    const maxPerAuthor = Math.max(2, Math.min(6, antiGaming.perCounterpartyCap));
    const minTier = getFlowThresholdTier(query.safety === "strict");
    const minTierRank = tierRank[minTier] ?? 0;
    const selectedPerAuthor = new Map<string, number>();

    const staged = candidateRows
      .map((row) => {
        const authorHash = String(row.author_subject_did_hash);
        const createdAt = Date.parse(String(row.created_at));
        const tier = tierByAuthor.get(authorHash) ?? "bronze";
        const diversity = diversityByAuthor.get(authorHash) ?? 0;
        return {
          row,
          authorHash,
          createdAt: Number.isFinite(createdAt) ? createdAt : 0,
          tier,
          diversity,
          sharedSpaces: sharedSpacesByAuthor.get(authorHash) ?? []
        };
      })
      .sort((a, b) => {
        if (b.createdAt !== a.createdAt) return b.createdAt - a.createdAt;
        const tierDelta = (tierRank[b.tier] ?? 0) - (tierRank[a.tier] ?? 0);
        if (tierDelta !== 0) return tierDelta;
        return b.diversity - a.diversity;
      });

    const filtered = staged.filter((entry) => {
      const privacy = privacyCache.get(entry.authorHash);
      if (privacy?.restricted || privacy?.tombstoned) return false;
      if ((tierRank[entry.tier] ?? 0) < minTierRank) return false;
      if (antiGaming.collusionClusterThreshold <= 0.8 && entry.diversity < 1) return false;
      const seen = selectedPerAuthor.get(entry.authorHash) ?? 0;
      if (seen >= maxPerAuthor) return false;
      if (query.trust === "verified_only") {
        if (!verifiedAuthorSet.has(entry.authorHash)) return false;
        if (moderatedAuthorSet.has(entry.authorHash)) return false;
      }
      if (query.trust === "trusted_creator" && (tierRank[entry.tier] ?? 0) < tierRank.silver) {
        return false;
      }
      if (query.trust === "space_members" && entry.sharedSpaces.length === 0) {
        return false;
      }
      selectedPerAuthor.set(entry.authorHash, seen + 1);
      return true;
    });

    const diversified = diversifyByAuthor(filtered, query.limit);
    const posts = diversified.map((entry) => ({
      post_id: entry.row.post_id,
      content_text: entry.row.content_text,
      content_hash: entry.row.content_hash,
      created_at: entry.row.created_at,
      trust_stamps: [
        entry.tier === "gold"
          ? "Trusted Creator"
          : entry.tier === "silver"
            ? "Verified Creator"
            : "Verified Account"
      ],
      explain_available: true
    }));
    return reply.send({
      mode: "flow",
      trust: query.trust ?? null,
      safety: query.safety ?? "default",
      posts
    });
  });

  app.get("/v1/social/post/:postId/explain", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    metrics.incCounter("social_explain_requests_total");
    const { postId } = explainPostParamsSchema.parse(request.params ?? {});
    const query = explainPostQuerySchema.parse(request.query ?? {});
    const db = await getDb();
    const post = await db("social_posts")
      .where({ post_id: postId })
      .whereNull("deleted_at")
      .first();
    if (!post) {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Post not found"));
    }
    const authorHash = String(post.author_subject_did_hash);
    const privacy = await getPrivacyStatus(authorHash).catch(() => ({
      restricted: false,
      tombstoned: false
    }));
    if (privacy.restricted || privacy.tombstoned) {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Post not found"));
    }
    const auraRow = (await db("aura_state")
      .where({ subject_did_hash: authorHash, domain: "social" })
      .select("state")
      .first()) as { state?: unknown } | undefined;
    const auraState = parseAuraState(auraRow?.state);
    const tier = normalizeTier(auraState.tier);
    const diversity = Number(auraState.diversity ?? 0);
    const viewerHash = query.viewerDid ? pseudonymizer.didToHash(query.viewerDid) : null;
    let sharedSpaceId: string | null = null;
    if (viewerHash) {
      const shared = await db("social_space_memberships as viewer")
        .join("social_space_memberships as author", "viewer.space_id", "author.space_id")
        .where("viewer.subject_did_hash", viewerHash)
        .andWhere("viewer.status", "ACTIVE")
        .andWhere("author.subject_did_hash", authorHash)
        .andWhere("author.status", "ACTIVE")
        .select("viewer.space_id")
        .first();
      sharedSpaceId = (shared?.space_id as string | undefined) ?? null;
    }

    const reasons: string[] = [];
    if (query.feedMode === "flow") {
      if (sharedSpaceId) reasons.push("You follow this Space");
      if ((tierRank[tier] ?? 0) >= tierRank.silver) reasons.push("Author has Trusted Creator tier");
      if (query.trust || query.safety === "strict")
        reasons.push("Matches your selected Trust Lens");
      if (diversity > 0) reasons.push("Recently active in your communities");
    } else {
      reasons.push("Recent post in your Signal feed");
    }
    if (reasons.length === 0) {
      reasons.push("Recent post in your network");
    }
    return reply.send({
      reasons,
      trustStampSummary: {
        tier,
        capability: (tierRank[tier] ?? 0) >= tierRank.silver ? "trusted_creator" : "can_post",
        domain: sharedSpaceId ? `space:${sharedSpaceId}` : "social"
      }
    });
  });

  app.post("/v1/social/media/emoji/create", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = emojiCreateSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const context = body.spaceId ? { space_id: body.spaceId } : undefined;
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "media.emoji.create",
      actionType: "emoji_create",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context
    }).catch(() => null);
    if (!gate) {
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const id = randomUUID();
    await (
      await getDb()
    )("media_emoji_assets").insert({
      id,
      creator_subject_hash: subjectDidHash,
      space_id: body.spaceId ?? null,
      asset_ref: body.assetRef,
      hash: body.assetHash ?? hashHex(body.assetRef),
      status: "ACTIVE",
      created_at: new Date().toISOString()
    });
    await logAction({
      subjectDidHash,
      actionType: "media.emoji.create",
      decision: "ALLOW",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    incCompleted("emoji_create");
    await logAction({
      subjectDidHash,
      actionType: "media.emoji.create",
      decision: "COMPLETE",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    return reply.send({ decision: "ALLOW", assetId: id });
  });

  app.post("/v1/social/media/emoji/pack/create", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = emojiPackCreateSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const context = body.spaceId ? { space_id: body.spaceId } : undefined;
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "media.emoji.pack.create",
      actionType: "emoji_pack_create",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context
    }).catch(() => null);
    if (!gate)
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    if (gate.denied) return reply.code(403).send(gate.denied);
    const packId = randomUUID();
    await (
      await getDb()
    )("media_emoji_packs").insert({
      id: packId,
      owner_subject_hash: subjectDidHash,
      space_id: body.spaceId ?? null,
      visibility: body.visibility,
      version: 1,
      created_at: new Date().toISOString()
    });
    await logAction({
      subjectDidHash,
      actionType: "media.emoji.pack.create",
      decision: "ALLOW",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    incCompleted("emoji_pack_create");
    await logAction({
      subjectDidHash,
      actionType: "media.emoji.pack.create",
      decision: "COMPLETE",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    return reply.send({ decision: "ALLOW", packId });
  });

  app.post("/v1/social/media/emoji/pack/add", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = emojiPackAddSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const db = await getDb();
    const pack = await db("media_emoji_packs")
      .where({ id: body.packId, owner_subject_hash: subjectDidHash })
      .first();
    if (!pack)
      return reply.code(404).send(makeErrorResponse("invalid_request", "Emoji pack not found"));
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "media.emoji.pack.create",
      actionType: "emoji_pack_create",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: pack.space_id ? { space_id: String(pack.space_id) } : undefined
    }).catch(() => null);
    if (!gate)
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    if (gate.denied) return reply.code(403).send(gate.denied);
    await db("media_emoji_pack_assets")
      .insert({ pack_id: body.packId, asset_id: body.assetId })
      .onConflict(["pack_id", "asset_id"])
      .ignore();
    return reply.send({ decision: "ALLOW" });
  });

  app.post("/v1/social/media/emoji/pack/publish", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = emojiPackPublishSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "media.emoji.pack.publish",
      actionType: "emoji_pack_publish",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (!gate)
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    if (gate.denied) return reply.code(403).send(gate.denied);
    await (await getDb())("media_emoji_packs")
      .where({ id: body.packId, owner_subject_hash: subjectDidHash })
      .update({
        space_id: body.spaceId,
        visibility: "space",
        published_at: new Date().toISOString()
      });
    await logAction({
      subjectDidHash,
      actionType: "media.emoji.pack.publish",
      decision: "ALLOW",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    incCompleted("emoji_pack_publish");
    await logAction({
      subjectDidHash,
      actionType: "media.emoji.pack.publish",
      decision: "COMPLETE",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    return reply.send({ decision: "ALLOW" });
  });

  app.post("/v1/social/media/soundpack/create", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = soundpackCreateSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "media.soundpack.create",
      actionType: "soundpack_create",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: body.spaceId ? { space_id: body.spaceId } : undefined
    }).catch(() => null);
    if (!gate)
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    if (gate.denied) return reply.code(403).send(gate.denied);
    const packId = randomUUID();
    await (
      await getDb()
    )("media_soundpacks").insert({
      id: packId,
      owner_subject_hash: subjectDidHash,
      space_id: body.spaceId ?? null,
      visibility: body.visibility,
      version: 1,
      created_at: new Date().toISOString()
    });
    await logAction({
      subjectDidHash,
      actionType: "media.soundpack.create",
      decision: "ALLOW",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    incCompleted("soundpack_create");
    await logAction({
      subjectDidHash,
      actionType: "media.soundpack.create",
      decision: "COMPLETE",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    return reply.send({ decision: "ALLOW", packId });
  });

  app.post("/v1/social/media/soundpack/add", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = soundAssetAddSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const db = await getDb();
    const pack = await db("media_soundpacks")
      .where({ id: body.packId, owner_subject_hash: subjectDidHash })
      .first();
    if (!pack)
      return reply.code(404).send(makeErrorResponse("invalid_request", "Soundpack not found"));
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "media.soundpack.create",
      actionType: "soundpack_create",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: pack.space_id ? { space_id: String(pack.space_id) } : undefined
    }).catch(() => null);
    if (!gate)
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    if (gate.denied) return reply.code(403).send(gate.denied);
    const assetId = randomUUID();
    await db("media_sound_assets").insert({
      id: assetId,
      creator_subject_hash: subjectDidHash,
      space_id: pack.space_id ?? null,
      asset_ref: body.assetRef,
      hash: body.assetHash ?? hashHex(body.assetRef),
      duration_ms: body.durationMs,
      created_at: new Date().toISOString()
    });
    await db("media_soundpack_assets")
      .insert({ pack_id: body.packId, asset_id: assetId })
      .onConflict(["pack_id", "asset_id"])
      .ignore();
    return reply.send({ decision: "ALLOW", assetId });
  });

  app.post("/v1/social/media/soundpack/publish", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = soundpackPublishSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "media.soundpack.publish",
      actionType: "soundpack_publish",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (!gate)
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    if (gate.denied) return reply.code(403).send(gate.denied);
    await (await getDb())("media_soundpacks")
      .where({ id: body.packId, owner_subject_hash: subjectDidHash })
      .update({
        space_id: body.spaceId,
        visibility: "space",
        published_at: new Date().toISOString()
      });
    await logAction({
      subjectDidHash,
      actionType: "media.soundpack.publish",
      decision: "ALLOW",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    incCompleted("soundpack_publish");
    await logAction({
      subjectDidHash,
      actionType: "media.soundpack.publish",
      decision: "COMPLETE",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    return reply.send({ decision: "ALLOW" });
  });

  app.post("/v1/social/media/soundpack/activate", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = soundpackActivateSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "media.soundpack.activate_in_space",
      actionType: "soundpack_activate",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (!gate)
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    if (gate.denied) return reply.code(403).send(gate.denied);
    const db = await getDb();
    const now = new Date().toISOString();
    await db.transaction(async (trx) => {
      await trx("media_soundpack_activations")
        .where({ space_id: body.spaceId })
        .whereNull("deactivated_at")
        .update({ deactivated_at: now });
      await trx("media_soundpack_activations").insert({
        space_id: body.spaceId,
        pack_id: body.packId,
        activated_by_subject_hash: subjectDidHash,
        activated_at: now
      });
    });
    await logAction({
      subjectDidHash,
      actionType: "media.soundpack.activate_in_space",
      decision: "ALLOW",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    incCompleted("soundpack_activate");
    await logAction({
      subjectDidHash,
      actionType: "media.soundpack.activate_in_space",
      decision: "COMPLETE",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    return reply.send({ decision: "ALLOW" });
  });

  app.post("/v1/social/presence/set_mode", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = presenceSetModeSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "presence.set_mode",
      actionType: "presence_set_mode",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (!gate)
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    if (gate.denied) return reply.code(403).send(gate.denied);
    await (
      await getDb()
    )("presence_space_states")
      .insert({
        space_id: body.spaceId,
        subject_hash: subjectDidHash,
        mode: body.mode,
        updated_at: new Date().toISOString()
      })
      .onConflict(["space_id", "subject_hash"])
      .merge({ mode: body.mode, updated_at: new Date().toISOString() });
    await logAction({
      subjectDidHash,
      actionType: "presence.set_mode",
      decision: "ALLOW",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    incCompleted("presence_set_mode");
    await logAction({
      subjectDidHash,
      actionType: "presence.set_mode",
      decision: "COMPLETE",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    return reply.send({ decision: "ALLOW" });
  });

  app.post("/v1/social/presence/invite", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = presenceInviteSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const inviteeHash = pseudonymizer.didToHash(body.inviteeDid);
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "presence.invite_to_session",
      actionType: "presence_invite",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (!gate)
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    if (gate.denied) return reply.code(403).send(gate.denied);
    const inviteId = randomUUID();
    await (
      await getDb()
    )("presence_invite_events").insert({
      id: inviteId,
      space_id: body.spaceId,
      inviter_hash: subjectDidHash,
      invitee_hash: inviteeHash,
      session_ref: body.sessionRef,
      status: "SENT",
      created_at: new Date().toISOString()
    });
    await logAction({
      subjectDidHash,
      actionType: "presence.invite_to_session",
      decision: "ALLOW",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    incCompleted("presence_invite");
    await logAction({
      subjectDidHash,
      actionType: "presence.invite_to_session",
      decision: "COMPLETE",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    return reply.send({ decision: "ALLOW", inviteId });
  });

  app.get("/v1/social/presence/state", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const query = presenceStateQuerySchema.parse(request.query ?? {});
    const rows = await (await getDb())("presence_space_states")
      .where({ space_id: query.spaceId })
      .orderBy("updated_at", "desc");
    return reply.send({
      space_id: query.spaceId,
      states: rows.map((row) => ({
        subject_hash: row.subject_hash,
        mode: row.mode,
        updated_at: row.updated_at
      }))
    });
  });

  app.post("/v1/social/sync/watch/create_session", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = watchCreateSessionSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "sync.watch.create_session",
      actionType: "watch_create",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (!gate)
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    if (gate.denied) return reply.code(403).send(gate.denied);
    const sessionId = randomUUID();
    const now = new Date().toISOString();
    const db = await getDb();
    await db.transaction(async (trx) => {
      await trx("sync_watch_sessions").insert({
        id: sessionId,
        space_id: body.spaceId,
        host_hash: subjectDidHash,
        created_at: now,
        status: "ACTIVE"
      });
      await trx("sync_watch_participants").insert({
        session_id: sessionId,
        subject_hash: subjectDidHash,
        joined_at: now
      });
    });
    await logAction({
      subjectDidHash,
      actionType: "sync.watch.create_session",
      decision: "ALLOW",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    incCompleted("watch_create");
    await logAction({
      subjectDidHash,
      actionType: "sync.watch.create_session",
      decision: "COMPLETE",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    return reply.send({ decision: "ALLOW", sessionId });
  });

  app.post("/v1/social/sync/watch/join_session", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = watchJoinSessionSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "sync.watch.join_session",
      actionType: "watch_join",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (!gate)
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    if (gate.denied) return reply.code(403).send(gate.denied);
    await (
      await getDb()
    )("sync_watch_participants")
      .insert({
        session_id: body.sessionId,
        subject_hash: subjectDidHash,
        joined_at: new Date().toISOString(),
        left_at: null
      })
      .onConflict(["session_id", "subject_hash"])
      .merge({ joined_at: new Date().toISOString(), left_at: null });
    await logAction({
      subjectDidHash,
      actionType: "sync.watch.join_session",
      decision: "ALLOW",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    incCompleted("watch_join");
    await logAction({
      subjectDidHash,
      actionType: "sync.watch.join_session",
      decision: "COMPLETE",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    return reply.send({ decision: "ALLOW" });
  });

  app.post("/v1/social/sync/watch/end_session", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = watchEndSessionSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "sync.watch.end_session",
      actionType: "watch_end",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (!gate)
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    if (gate.denied) return reply.code(403).send(gate.denied);
    const now = new Date().toISOString();
    const db = await getDb();
    await db.transaction(async (trx) => {
      await trx("sync_watch_sessions")
        .where({ id: body.sessionId, space_id: body.spaceId })
        .update({ ended_at: now, status: "ENDED" });
      await trx("sync_watch_participants")
        .where({ session_id: body.sessionId })
        .whereNull("left_at")
        .update({ left_at: now });
    });
    await logAction({
      subjectDidHash,
      actionType: "sync.watch.end_session",
      decision: "ALLOW",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    incCompleted("watch_end");
    await logAction({
      subjectDidHash,
      actionType: "sync.watch.end_session",
      decision: "COMPLETE",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    return reply.send({ decision: "ALLOW" });
  });

  app.post("/v1/social/sync/scroll/create_session", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = syncCreateSessionSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "sync.scroll.create_session",
      actionType: "scroll_create",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (!gate) {
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const space = await getSpaceById(body.spaceId);
    if (!space)
      return reply.code(404).send(makeErrorResponse("invalid_request", "Space not found"));
    if (!(await hasActiveSpaceMembership(body.spaceId, subjectDidHash))) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", "Space membership required"));
    }
    const now = new Date().toISOString();
    const sessionId = randomUUID();
    await (
      await getDb()
    ).transaction(async (trx) => {
      await trx("sync_sessions").insert({
        session_id: sessionId,
        space_id: body.spaceId,
        kind: "scroll",
        host_subject_did_hash: subjectDidHash,
        status: "ACTIVE",
        created_at: now,
        policy_pack_id: space.policy_pack_id ?? null
      });
      await trx("sync_session_participants").insert({
        session_id: sessionId,
        subject_did_hash: subjectDidHash,
        role: "host",
        joined_at: now
      });
    });
    await logAction({
      subjectDidHash,
      actionType: "sync.scroll.create_session",
      decision: "ALLOW",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    incCompleted("scroll_create");
    await logAction({
      subjectDidHash,
      actionType: "sync.scroll.create_session",
      decision: "COMPLETE",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    return reply.send({ decision: "ALLOW", sessionId });
  });

  app.post("/v1/social/sync/scroll/join_session", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = syncJoinSessionSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const sessionAccess = await ensureSyncSessionAccess({
      sessionId: body.sessionId,
      spaceId: body.spaceId,
      expectedKind: "scroll"
    });
    if (!sessionAccess.session) {
      return reply.code(404).send(sessionAccess.error);
    }
    if (sessionAccess.session.status !== "ACTIVE") {
      return reply.code(409).send(makeErrorResponse("invalid_request", "Session already ended"));
    }
    if (!(await hasActiveSpaceMembership(body.spaceId, subjectDidHash))) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", "Space membership required"));
    }
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "sync.scroll.join_session",
      actionType: "scroll_join",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (!gate) {
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    await (
      await getDb()
    )("sync_session_participants")
      .insert({
        session_id: body.sessionId,
        subject_did_hash: subjectDidHash,
        role:
          sessionAccess.session.host_subject_did_hash === subjectDidHash ? "host" : "participant",
        joined_at: new Date().toISOString(),
        left_at: null
      })
      .onConflict(["session_id", "subject_did_hash"])
      .merge({ left_at: null, joined_at: new Date().toISOString() });
    const permission = await mintSyncPermissionToken({
      sessionId: body.sessionId,
      subjectDidHash
    });
    await logAction({
      subjectDidHash,
      actionType: "sync.scroll.join_session",
      decision: "ALLOW",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    incCompleted("scroll_join");
    await logAction({
      subjectDidHash,
      actionType: "sync.scroll.join_session",
      decision: "COMPLETE",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    return reply.send({
      decision: "ALLOW",
      permissionToken: permission.token,
      permissionExpiresAt: permission.expiresAt
    });
  });

  app.post("/v1/social/sync/scroll/sync_event", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = syncEventPayloadSchema.parse(request.body ?? {});
    const session = await getSyncSession(body.sessionId);
    if (!session || session.kind !== "scroll") {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Scroll session not found"));
    }
    if (session.status !== "ACTIVE") {
      return reply.code(409).send(makeErrorResponse("invalid_request", "Session already ended"));
    }
    const permission = await validateSyncPermission({
      sessionId: body.sessionId,
      permissionToken: body.permissionToken
    });
    if (!permission.ok) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", `Permission denied (${permission.reason})`));
    }
    if (!(await hasActiveSpaceMembership(session.space_id, permission.subjectDidHash))) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", "Space membership required"));
    }
    const participant = await (
      await getDb()
    )("sync_session_participants")
      .where({
        session_id: body.sessionId,
        subject_did_hash: permission.subjectDidHash
      })
      .whereNull("left_at")
      .first();
    if (!participant) {
      return reply.code(403).send(makeErrorResponse("invalid_request", "Join session first"));
    }
    const payloadText = JSON.stringify(body.payload ?? null);
    const payloadBytes = new TextEncoder().encode(payloadText).byteLength;
    if (payloadBytes > config.SYNC_SESSION_EVENT_MAX_PAYLOAD_BYTES) {
      return reply.code(413).send(
        makeErrorResponse("invalid_request", "Event payload exceeds max size", {
          devMode: config.DEV_MODE,
          debug: { hint: `max_bytes=${config.SYNC_SESSION_EVENT_MAX_PAYLOAD_BYTES}` }
        })
      );
    }
    const rate = await checkSyncEventRateLimit({
      permissionHash: permission.permissionHash,
      subjectDidHash: permission.subjectDidHash,
      spaceId: session.space_id
    });
    if (!rate.allowed) {
      return reply.code(429).send(
        makeErrorResponse("invalid_request", "Event rate limit exceeded", {
          devMode: config.DEV_MODE,
          debug: { hint: `tier=${rate.tier}` }
        })
      );
    }
    await pruneExpiredSyncEvents().catch(() => undefined);
    const eventId = randomUUID();
    const now = new Date().toISOString();
    const payloadHash = hashCanonicalJson(body.payload ?? null);
    await (
      await getDb()
    )("sync_session_events").insert({
      event_id: eventId,
      session_id: body.sessionId,
      actor_subject_did_hash: permission.subjectDidHash,
      event_type: body.eventType,
      payload_json: body.payload ?? null,
      payload_hash: payloadHash,
      created_at: now
    });
    broadcastSyncEvent(body.sessionId, {
      type: "sync_event",
      event: {
        event_id: eventId,
        session_id: body.sessionId,
        actor_subject_did_hash: permission.subjectDidHash,
        event_type: body.eventType,
        payload_json: body.payload ?? null,
        payload_hash: payloadHash,
        created_at: now
      }
    });
    incCompleted("scroll_event");
    return reply.send({ decision: "ALLOW", eventId, payloadHash });
  });

  app.post("/v1/social/sync/scroll/end_session", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = syncJoinSessionSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const sessionAccess = await ensureSyncSessionAccess({
      sessionId: body.sessionId,
      spaceId: body.spaceId,
      expectedKind: "scroll"
    });
    if (!sessionAccess.session) {
      return reply.code(404).send(sessionAccess.error);
    }
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "sync.scroll.end_session",
      actionType: "scroll_end",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (!gate) {
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    if (sessionAccess.session.host_subject_did_hash !== subjectDidHash) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", "Only host can end session"));
    }
    const now = new Date().toISOString();
    await (
      await getDb()
    ).transaction(async (trx) => {
      await trx("sync_sessions")
        .where({ session_id: body.sessionId, space_id: body.spaceId })
        .update({ status: "ENDED", ended_at: now });
      await trx("sync_session_participants")
        .where({ session_id: body.sessionId })
        .whereNull("left_at")
        .update({ left_at: now });
      await trx("sync_session_permissions").where({ session_id: body.sessionId }).del();
    });
    broadcastSyncEvent(body.sessionId, {
      type: "session_ended",
      session_id: body.sessionId,
      ended_at: now
    });
    incCompleted("scroll_end");
    return reply.send({ decision: "ALLOW" });
  });

  app.post("/v1/social/sync/listen/create_session", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = syncCreateSessionSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "sync.listen.create_session",
      actionType: "listen_create",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (!gate) {
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    if (!(await hasActiveSpaceMembership(body.spaceId, subjectDidHash))) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", "Space membership required"));
    }
    const sessionId = randomUUID();
    const now = new Date().toISOString();
    const space = await getSpaceById(body.spaceId);
    await (
      await getDb()
    ).transaction(async (trx) => {
      await trx("sync_sessions").insert({
        session_id: sessionId,
        space_id: body.spaceId,
        kind: "listen",
        host_subject_did_hash: subjectDidHash,
        status: "ACTIVE",
        created_at: now,
        policy_pack_id: space?.policy_pack_id ?? null
      });
      await trx("sync_session_participants").insert({
        session_id: sessionId,
        subject_did_hash: subjectDidHash,
        role: "host",
        joined_at: now
      });
    });
    incCompleted("listen_create");
    return reply.send({ decision: "ALLOW", sessionId });
  });

  app.post("/v1/social/sync/listen/join_session", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = syncJoinSessionSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const sessionAccess = await ensureSyncSessionAccess({
      sessionId: body.sessionId,
      spaceId: body.spaceId,
      expectedKind: "listen"
    });
    if (!sessionAccess.session) {
      return reply.code(404).send(sessionAccess.error);
    }
    if (sessionAccess.session.status !== "ACTIVE") {
      return reply.code(409).send(makeErrorResponse("invalid_request", "Session already ended"));
    }
    if (!(await hasActiveSpaceMembership(body.spaceId, subjectDidHash))) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", "Space membership required"));
    }
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "sync.listen.join_session",
      actionType: "listen_join",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (!gate) {
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    await (
      await getDb()
    )("sync_session_participants")
      .insert({
        session_id: body.sessionId,
        subject_did_hash: subjectDidHash,
        role:
          sessionAccess.session.host_subject_did_hash === subjectDidHash ? "host" : "participant",
        joined_at: new Date().toISOString(),
        left_at: null
      })
      .onConflict(["session_id", "subject_did_hash"])
      .merge({ left_at: null, joined_at: new Date().toISOString() });
    const permission = await mintSyncPermissionToken({
      sessionId: body.sessionId,
      subjectDidHash
    });
    incCompleted("listen_join");
    return reply.send({
      decision: "ALLOW",
      permissionToken: permission.token,
      permissionExpiresAt: permission.expiresAt
    });
  });

  app.post("/v1/social/sync/listen/broadcast_control", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = syncEventPayloadSchema.parse(request.body ?? {});
    const session = await getSyncSession(body.sessionId);
    if (!session || session.kind !== "listen") {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Listen session not found"));
    }
    if (session.status !== "ACTIVE") {
      return reply.code(409).send(makeErrorResponse("invalid_request", "Session already ended"));
    }
    const permission = await validateSyncPermission({
      sessionId: body.sessionId,
      permissionToken: body.permissionToken
    });
    if (!permission.ok) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", `Permission denied (${permission.reason})`));
    }
    if (!(await hasActiveSpaceMembership(session.space_id, permission.subjectDidHash))) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", "Space membership required"));
    }
    const participant = await (
      await getDb()
    )("sync_session_participants")
      .where({
        session_id: body.sessionId,
        subject_did_hash: permission.subjectDidHash
      })
      .whereNull("left_at")
      .first();
    if (!participant) {
      return reply.code(403).send(makeErrorResponse("invalid_request", "Join session first"));
    }
    const payloadText = JSON.stringify(body.payload ?? null);
    const payloadBytes = new TextEncoder().encode(payloadText).byteLength;
    if (payloadBytes > config.SYNC_SESSION_EVENT_MAX_PAYLOAD_BYTES) {
      return reply.code(413).send(
        makeErrorResponse("invalid_request", "Event payload exceeds max size", {
          devMode: config.DEV_MODE,
          debug: { hint: `max_bytes=${config.SYNC_SESSION_EVENT_MAX_PAYLOAD_BYTES}` }
        })
      );
    }
    const rate = await checkSyncEventRateLimit({
      permissionHash: permission.permissionHash,
      subjectDidHash: permission.subjectDidHash,
      spaceId: session.space_id
    });
    if (!rate.allowed) {
      return reply.code(429).send(
        makeErrorResponse("invalid_request", "Event rate limit exceeded", {
          devMode: config.DEV_MODE,
          debug: { hint: `tier=${rate.tier}` }
        })
      );
    }
    await pruneExpiredSyncEvents().catch(() => undefined);
    const eventId = randomUUID();
    const now = new Date().toISOString();
    const payloadHash = hashCanonicalJson(body.payload ?? null);
    await (
      await getDb()
    )("sync_session_events").insert({
      event_id: eventId,
      session_id: body.sessionId,
      actor_subject_did_hash: permission.subjectDidHash,
      event_type: body.eventType === "LISTEN_STATE" ? "LISTEN_STATE" : "REACTION",
      payload_json: body.payload ?? null,
      payload_hash: payloadHash,
      created_at: now
    });
    broadcastSyncEvent(body.sessionId, {
      type: "sync_event",
      event: {
        event_id: eventId,
        session_id: body.sessionId,
        actor_subject_did_hash: permission.subjectDidHash,
        event_type: body.eventType === "LISTEN_STATE" ? "LISTEN_STATE" : "REACTION",
        payload_json: body.payload ?? null,
        payload_hash: payloadHash,
        created_at: now
      }
    });
    incCompleted("listen_event");
    return reply.send({ decision: "ALLOW", eventId, payloadHash });
  });

  app.post("/v1/social/sync/listen/end_session", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = syncJoinSessionSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const sessionAccess = await ensureSyncSessionAccess({
      sessionId: body.sessionId,
      spaceId: body.spaceId,
      expectedKind: "listen"
    });
    if (!sessionAccess.session) {
      return reply.code(404).send(sessionAccess.error);
    }
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "sync.listen.end_session",
      actionType: "listen_end",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (!gate) {
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    if (sessionAccess.session.host_subject_did_hash !== subjectDidHash) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", "Only host can end session"));
    }
    const now = new Date().toISOString();
    await (
      await getDb()
    ).transaction(async (trx) => {
      await trx("sync_sessions")
        .where({ session_id: body.sessionId, space_id: body.spaceId })
        .update({ status: "ENDED", ended_at: now });
      await trx("sync_session_participants")
        .where({ session_id: body.sessionId })
        .whereNull("left_at")
        .update({ left_at: now });
      await trx("sync_session_permissions").where({ session_id: body.sessionId }).del();
    });
    broadcastSyncEvent(body.sessionId, {
      type: "session_ended",
      session_id: body.sessionId,
      ended_at: now
    });
    incCompleted("listen_end");
    return reply.send({ decision: "ALLOW" });
  });

  app.post("/v1/social/sync/session/report", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = syncSessionReportV02Schema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const sessionAccess = await ensureSyncSessionAccess({
      sessionId: body.sessionId,
      spaceId: body.spaceId
    });
    if (!sessionAccess.session) {
      return reply.code(404).send(sessionAccess.error);
    }
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "sync.session.report",
      actionType: "emoji_asset_report",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (!gate) {
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const reportId = randomUUID();
    const now = new Date().toISOString();
    await (
      await getDb()
    ).transaction(async (trx) => {
      await trx("sync_session_reports").insert({
        report_id: reportId,
        session_id: body.sessionId,
        reporter_subject_did_hash: subjectDidHash,
        reason_code: body.reasonCode,
        created_at: now
      });
      await trx("social_reports").insert({
        report_id: reportId,
        reporter_subject_did_hash: subjectDidHash,
        space_id: body.spaceId,
        reason_code: `${body.reasonCode}:sync_session:${body.sessionId}`,
        created_at: now
      });
      await trx("social_space_moderation_cases")
        .insert({
          case_id: randomUUID(),
          space_id: body.spaceId,
          report_id: reportId,
          status: "OPEN",
          created_at: now,
          updated_at: now
        })
        .onConflict("report_id")
        .ignore();
    });
    return reply.send({ decision: "ALLOW", reportId });
  });

  app.post("/v1/social/sync/session/moderate", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = syncSessionModerateV02Schema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const sessionAccess = await ensureSyncSessionAccess({
      sessionId: body.sessionId,
      spaceId: body.spaceId
    });
    if (!sessionAccess.session) {
      return reply.code(404).send(sessionAccess.error);
    }
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "sync.session.moderate",
      actionType: "space_moderate",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (!gate) {
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const now = new Date().toISOString();
    const targetSubjectDidHash = body.targetSubjectDid
      ? pseudonymizer.didToHash(body.targetSubjectDid)
      : null;
    const auditPayload = {
      sessionId: body.sessionId,
      operation: body.operation,
      reasonCode: body.reasonCode,
      spaceId: body.spaceId,
      moderatorSubjectDidHash: subjectDidHash,
      targetSubjectDidHash
    };
    const auditHash = hashCanonicalJson(auditPayload);
    await (
      await getDb()
    ).transaction(async (trx) => {
      if (body.operation === "kick_participant") {
        if (!targetSubjectDidHash) {
          throw new Error("target_subject_required");
        }
        await trx("sync_session_participants")
          .where({ session_id: body.sessionId, subject_did_hash: targetSubjectDidHash })
          .whereNull("left_at")
          .update({ left_at: now });
        await trx("sync_session_permissions")
          .where({ session_id: body.sessionId, subject_did_hash: targetSubjectDidHash })
          .del();
      } else {
        await trx("sync_sessions")
          .where({ session_id: body.sessionId })
          .update({ status: "ENDED", ended_at: now });
        await trx("sync_session_participants")
          .where({ session_id: body.sessionId })
          .whereNull("left_at")
          .update({ left_at: now });
        await trx("sync_session_permissions").where({ session_id: body.sessionId }).del();
      }
      await trx("social_space_moderation_actions").insert({
        moderation_id: randomUUID(),
        space_id: body.spaceId,
        moderator_subject_did_hash: subjectDidHash,
        target_subject_did_hash: targetSubjectDidHash,
        target_space_post_id: null,
        operation: body.operation === "kick_participant" ? "restrict_member" : "remove_content",
        reason_code: `sync:${body.reasonCode}`,
        audit_hash: auditHash,
        anchor_requested: body.anchor ?? false,
        created_at: now
      });
      if (body.anchor && config.ANCHOR_AUTH_SECRET) {
        await trx("anchor_outbox")
          .insert({
            outbox_id: randomUUID(),
            event_type: "SYNC_SESSION_MODERATION",
            payload_hash: auditHash,
            payload_meta: {
              action: "sync.session.moderate",
              operation: body.operation,
              session_id_hash: hashHex(body.sessionId),
              space_id_hash: hashHex(body.spaceId),
              moderator_subject_did_hash: subjectDidHash,
              ...signAnchorMeta(config.ANCHOR_AUTH_SECRET, {
                payloadHash: auditHash,
                eventType: "SYNC_SESSION_MODERATION"
              })
            },
            status: "PENDING",
            attempts: 0,
            next_retry_at: now,
            created_at: now,
            updated_at: now
          })
          .onConflict("payload_hash")
          .ignore();
      }
    });
    if (body.operation === "end_session") {
      broadcastSyncEvent(body.sessionId, {
        type: "session_ended",
        session_id: body.sessionId,
        ended_at: now
      });
    } else if (targetSubjectDidHash) {
      broadcastSyncEvent(body.sessionId, {
        type: "participant_removed",
        session_id: body.sessionId,
        target_subject_did_hash: targetSubjectDidHash
      });
    }
    return reply.send({ decision: "ALLOW", auditHash });
  });

  app.get(
    "/v1/social/sync/session/:sessionId/stream",
    { websocket: true },
    async (connection, request: FastifyRequest) => {
      const paramsParsed = syncSessionStreamParamsSchema.safeParse(request.params ?? {});
      const queryParsed = syncSessionStreamQuerySchema.safeParse(request.query ?? {});
      if (!paramsParsed.success || !queryParsed.success) {
        connection.socket.send(
          JSON.stringify({
            type: "error",
            code: "invalid_request",
            message: "Invalid stream parameters"
          })
        );
        connection.socket.close(1008, "invalid_request");
        return;
      }
      const sessionId = paramsParsed.data.sessionId;
      const permissionToken = queryParsed.data.permission_token;
      const permission = await validateSyncPermission({
        sessionId,
        permissionToken
      });
      if (!permission.ok) {
        connection.socket.send(
          JSON.stringify({ type: "error", code: "permission_denied", message: permission.reason })
        );
        connection.socket.close(1008, "permission_denied");
        return;
      }
      const session = await getSyncSession(sessionId);
      if (!session || session.status !== "ACTIVE") {
        connection.socket.send(
          JSON.stringify({
            type: "error",
            code: "session_invalid",
            message: "Session is not active"
          })
        );
        connection.socket.close(1008, "session_invalid");
        return;
      }
      const participant = await (await getDb())("sync_session_participants")
        .where({ session_id: sessionId, subject_did_hash: permission.subjectDidHash })
        .whereNull("left_at")
        .first();
      if (!participant) {
        connection.socket.send(
          JSON.stringify({ type: "error", code: "not_participant", message: "Join session first" })
        );
        connection.socket.close(1008, "not_participant");
        return;
      }
      const subscriber: SyncSubscriber = {
        socket: connection.socket,
        subjectDidHash: permission.subjectDidHash,
        permissionHash: permission.permissionHash
      };
      addSyncSubscriber(sessionId, subscriber);
      connection.socket.send(
        JSON.stringify({
          type: "ready",
          session_id: sessionId,
          mode: session.kind
        })
      );
      connection.socket.on("close", () => {
        removeSyncSubscriber(sessionId, subscriber);
      });
      connection.socket.on("error", () => {
        removeSyncSubscriber(sessionId, subscriber);
      });
    }
  );

  app.post("/v1/social/media/asset/report", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = mediaAssetReportSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "media.asset.report",
      actionType: "emoji_asset_report",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (!gate)
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    if (gate.denied) return reply.code(403).send(gate.denied);
    const now = new Date().toISOString();
    const reportId = randomUUID();
    await (
      await getDb()
    ).transaction(async (trx) => {
      await trx("social_reports").insert({
        report_id: reportId,
        reporter_subject_did_hash: subjectDidHash,
        space_id: body.spaceId,
        reason_code: `${body.reasonCode}:asset:${body.assetId}`,
        created_at: now
      });
      await trx("social_space_moderation_cases")
        .insert({
          case_id: randomUUID(),
          space_id: body.spaceId,
          report_id: reportId,
          status: "OPEN",
          created_at: now,
          updated_at: now
        })
        .onConflict("report_id")
        .ignore();
    });
    await logAction({
      subjectDidHash,
      actionType: "media.asset.report",
      decision: "ALLOW",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    incCompleted("emoji_asset_report");
    await logAction({
      subjectDidHash,
      actionType: "media.asset.report",
      decision: "COMPLETE",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    return reply.send({ decision: "ALLOW", reportId });
  });

  app.post("/v1/social/media/asset/moderate", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = mediaAssetModerateSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "media.asset.moderate",
      actionType: "space_moderate",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (!gate)
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    if (gate.denied) return reply.code(403).send(gate.denied);
    const db = await getDb();
    const now = new Date().toISOString();
    if (body.assetId) {
      await db("media_emoji_assets")
        .where({ id: body.assetId, space_id: body.spaceId })
        .update({ status: "MODERATED", deleted_at: now });
    }
    if (body.caseId) {
      await db("social_space_moderation_cases")
        .where({ case_id: body.caseId, space_id: body.spaceId })
        .update({ status: body.resolution, updated_at: now });
    }
    return reply.send({ decision: "ALLOW", status: body.resolution });
  });

  app.post("/v1/social/sync/watch/report", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = syncSessionReportSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "sync.session.report",
      actionType: "emoji_asset_report",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (!gate)
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    if (gate.denied) return reply.code(403).send(gate.denied);
    const reportId = randomUUID();
    const now = new Date().toISOString();
    await (
      await getDb()
    ).transaction(async (trx) => {
      await trx("social_reports").insert({
        report_id: reportId,
        reporter_subject_did_hash: subjectDidHash,
        space_id: body.spaceId,
        reason_code: `${body.reasonCode}:sync_session:${body.sessionId}`,
        created_at: now
      });
      await trx("social_space_moderation_cases")
        .insert({
          case_id: randomUUID(),
          space_id: body.spaceId,
          report_id: reportId,
          status: "OPEN",
          created_at: now,
          updated_at: now
        })
        .onConflict("report_id")
        .ignore();
    });
    return reply.send({ decision: "ALLOW", reportId });
  });

  app.post("/v1/social/sync/watch/moderate", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = syncSessionModerateSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "sync.session.moderate",
      actionType: "space_moderate",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (!gate)
      return reply
        .code(503)
        .send(
          makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
            devMode: config.DEV_MODE
          })
        );
    if (gate.denied) return reply.code(403).send(gate.denied);
    await (await getDb())("social_space_moderation_cases")
      .where({ case_id: body.caseId, space_id: body.spaceId })
      .update({ status: body.resolution, updated_at: new Date().toISOString() });
    return reply.send({ decision: "ALLOW", status: body.resolution });
  });

  app.get("/v1/social/funnel", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    return reply.send({ funnel });
  });
};
