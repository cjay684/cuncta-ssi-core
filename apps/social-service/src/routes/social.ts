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
import {
  buildMediaObjectKey,
  createPresignedGet,
  createPresignedUpload,
  deleteMediaObjects,
  generateThumbnail,
  verifyUploadedObject
} from "../mediaStorage.js";

const pseudonymizer = createHmacSha256Pseudonymizer({ pepper: config.PSEUDONYMIZER_PEPPER });
const textEncoder = new TextEncoder();
const hashHex = (value: string) => createHash("sha256").update(value).digest("hex");
export const mediaStorageAdapter = {
  createPresignedGet,
  deleteMediaObjects
};

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
  imageRefs: z.array(z.string().uuid()).max(8).optional().default([]),
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
  imageRefs: z.array(z.string().uuid()).max(8).optional().default([]),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});

const mediaUploadRequestSchema = z.object({
  subjectDid: z.string().min(3),
  spaceId: z.string().uuid().optional(),
  mimeType: z.enum(["image/jpeg", "image/png", "image/webp", "image/gif"]),
  byteSize: z.number().int().min(1024).max(config.MEDIA_MAX_UPLOAD_BYTES),
  sha256Hex: z.string().trim().regex(/^[a-f0-9]{64}$/),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});

const mediaUploadCompleteSchema = z.object({
  subjectDid: z.string().min(3),
  assetId: z.string().uuid(),
  objectKey: z.string().trim().min(8).max(500),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});

const mediaViewRequestSchema = z.object({
  viewerDid: z.string().min(3).optional(),
  items: z
    .array(
      z.object({
        assetId: z.string().uuid(),
        context: z.discriminatedUnion("kind", [
          z.object({
            kind: z.literal("post"),
            postId: z.string().uuid()
          }),
          z.object({
            kind: z.literal("spacePost"),
            spaceId: z.string().uuid(),
            postId: z.string().uuid()
          })
        ])
      })
    )
    .min(1)
    .max(20)
});

const realtimeTokenSchema = z.object({
  subjectDid: z.string().min(3),
  channel: z.enum(["presence", "banter", "hangout", "challenge"]),
  spaceId: z.string().uuid(),
  threadId: z.string().uuid().optional(),
  sessionId: z.string().uuid().optional(),
  challengeId: z.string().uuid().optional(),
  canBroadcast: z.boolean().optional().default(false),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});

const realtimePublishSchema = z.object({
  permissionToken: z.string().min(16),
  eventType: z.string().trim().min(3).max(80),
  payload: z.unknown()
});

const realtimeEventsQuerySchema = z.object({
  permissionToken: z.string().min(16),
  since: z.string().datetime().optional(),
  after: z.string().regex(/^\d+$/).optional(),
  limit: z.coerce.number().int().min(1).max(200).default(100)
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
  mode: z.enum(["quiet", "active", "immersive"]),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const presencePingSchema = z.object({
  subjectDid: z.string().min(3),
  mode: z.enum(["quiet", "active", "immersive"]).optional(),
  crewId: z.string().uuid().optional(),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const spacePresenceQuerySchema = z.object({
  subjectDid: z.string().min(3).optional()
});
const profileVisibilitySchema = z.object({
  subjectDid: z.string().min(3),
  showOnLeaderboard: z.boolean().optional().default(false),
  showOnPresence: z.boolean().optional().default(false),
  presenceLabel: z.string().trim().min(1).max(64).optional(),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const ritualCreateSchema = z.object({
  subjectDid: z.string().min(3),
  spaceId: z.string().uuid(),
  title: z.string().trim().min(3).max(120),
  description: z.string().trim().max(300).optional(),
  durationMinutes: z.number().int().min(5).max(60).default(10),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const ritualParticipateSchema = z.object({
  subjectDid: z.string().min(3),
  ritualId: z.string().uuid(),
  spaceId: z.string().uuid(),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const ritualCompleteSchema = z.object({
  subjectDid: z.string().min(3),
  ritualId: z.string().uuid(),
  spaceId: z.string().uuid(),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const ritualEndSchema = z.object({
  subjectDid: z.string().min(3),
  ritualId: z.string().uuid(),
  spaceId: z.string().uuid(),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const crewCreateSchema = z.object({
  subjectDid: z.string().min(3),
  name: z.string().trim().min(2).max(64),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const crewJoinSchema = z.object({
  subjectDid: z.string().min(3),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const crewInviteSchema = z.object({
  subjectDid: z.string().min(3),
  inviteeDid: z.string().min(3),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const crewLeaveSchema = z.object({
  subjectDid: z.string().min(3)
});
const crewPresenceQuerySchema = z.object({
  subjectDid: z.string().min(3).optional()
});
const challengeCreateSchema = z.object({
  subjectDid: z.string().min(3),
  cadence: z.enum(["daily", "weekly", "ad_hoc"]).default("daily"),
  title: z.string().trim().min(3).max(120),
  durationHours: z
    .number()
    .int()
    .min(1)
    .max(24 * 14)
    .default(24),
  crewId: z.string().uuid().optional(),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const challengeJoinSchema = z.object({
  subjectDid: z.string().min(3),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const challengeCompleteSchema = z.object({
  subjectDid: z.string().min(3),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const challengeEndSchema = z.object({
  subjectDid: z.string().min(3),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const banterThreadCreateSchema = z.object({
  subjectDid: z.string().min(3),
  kind: z.enum(["space_chat", "challenge_chat", "hangout_chat", "crew_chat"]),
  crewId: z.string().uuid().optional(),
  challengeId: z.string().uuid().optional(),
  hangoutSessionId: z.string().uuid().optional(),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const banterThreadListQuerySchema = z.object({
  kind: z.enum(["space_chat", "challenge_chat", "hangout_chat", "crew_chat"]).optional()
});
const banterThreadParamsSchema = z.object({
  threadId: z.string().uuid()
});
const banterMessagesQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(50).default(50),
  before: z.string().datetime().optional(),
  viewerDid: z.string().min(3).optional()
});
const banterPermissionSchema = z.object({
  subjectDid: z.string().min(3),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const banterSendSchema = z.object({
  subjectDid: z.string().min(3),
  bodyText: z.string().trim().min(1).max(280),
  permissionToken: z.string().min(16),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const banterReactSchema = z.object({
  subjectDid: z.string().min(3),
  permissionToken: z.string().min(16),
  emojiShortcode: z.string().trim().min(1).max(32).optional(),
  emojiId: z.string().uuid().optional(),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const banterMessageParamsSchema = z.object({
  messageId: z.string().uuid()
});
const banterDeleteOwnSchema = z.object({
  subjectDid: z.string().min(3),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const banterModerateSchema = z.object({
  subjectDid: z.string().min(3),
  reasonCode: z.string().trim().min(2).max(64).default("banter_removed"),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const spaceStatusSetSchema = z.object({
  subjectDid: z.string().min(3),
  crewId: z.string().uuid().optional(),
  mode: z.enum(["quiet", "active", "immersive"]).default("active"),
  statusText: z.string().trim().min(1).max(80),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const spaceStatusQuerySchema = z.object({
  viewerDid: z.string().min(3).optional()
});
const rankingsQuerySchema = z.object({
  type: z.enum(["contributors", "streaks"]).default("contributors")
});
const leaderboardQuerySchema = z.object({
  window: z.enum(["7d", "14d"]).default("7d")
});
const pulseQuerySchema = z.object({
  subjectDid: z.string().min(3).optional()
});
const pulsePreferencesUpdateSchema = z.object({
  subjectDid: z.string().min(3),
  enabled: z.boolean().optional(),
  notifyHangouts: z.boolean().optional(),
  notifyCrews: z.boolean().optional(),
  notifyChallenges: z.boolean().optional(),
  notifyRankings: z.boolean().optional(),
  notifyStreaks: z.boolean().optional(),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const huddleCreateSessionSchema = z.object({
  subjectDid: z.string().min(3),
  spaceId: z.string().uuid(),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const huddleJoinSessionSchema = z.object({
  subjectDid: z.string().min(3),
  sessionId: z.string().uuid(),
  spaceId: z.string().uuid(),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3)
});
const huddleEndSessionSchema = z.object({
  subjectDid: z.string().min(3),
  sessionId: z.string().uuid(),
  spaceId: z.string().uuid(),
  reasonCode: z.string().trim().min(2).max(64).default("ended_by_host"),
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
  | "listen_end"
  | "presence_ping"
  | "huddle_create"
  | "huddle_join"
  | "huddle_end"
  | "ritual_create"
  | "ritual_participate"
  | "ritual_complete"
  | "ritual_end"
  | "crew_create"
  | "crew_join"
  | "crew_invite"
  | "crew_leave"
  | "challenge_create"
  | "challenge_join"
  | "challenge_complete"
  | "challenge_end"
  | "hangout_create"
  | "hangout_join"
  | "hangout_end"
  | "media_view"
  | "banter_thread_create"
  | "banter_message_send"
  | "banter_message_react"
  | "banter_message_delete_own"
  | "banter_message_moderate"
  | "banter_status_set";
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

// Policy service is the authoritative source of requirement labels (data-driven).
const requirementLabel = (vct: string, label?: string) => {
  const trimmed = typeof label === "string" ? label.trim() : "";
  return trimmed.length ? trimmed : vct;
};
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
  listen_end: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  presence_ping: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  huddle_create: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  huddle_join: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  huddle_end: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  ritual_create: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  ritual_participate: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  ritual_complete: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  ritual_end: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  crew_create: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  crew_join: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  crew_invite: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  crew_leave: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  challenge_create: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  challenge_join: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  challenge_complete: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  challenge_end: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  hangout_create: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  hangout_join: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  hangout_end: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  media_view: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  banter_thread_create: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  banter_message_send: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  banter_message_react: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  banter_message_delete_own: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  banter_message_moderate: { attempts: 0, allowed: 0, denied: 0, completed: 0 },
  banter_status_set: { attempts: 0, allowed: 0, denied: 0, completed: 0 }
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
const presencePingBuckets = new Map<string, { count: number; startedAt: number }>();
const banterMessageBuckets = new Map<
  string,
  { count: number; startedAt: number; cooldownUntil?: number }
>();
const realtimeBroadcastBuckets = new Map<string, { count: number; startedAt: number }>();
const mediaViewBuckets = new Map<string, { count: number; startedAt: number }>();
const MEDIA_VIEW_RATE_LIMIT_WINDOW_MS = 60_000;
const MEDIA_VIEW_RATE_LIMIT_MAX = 60;
const MAX_POST_IMAGE_REFS = 4;
const MEDIA_UPLOAD_CLEANUP_INTERVAL_MS = 5 * 60 * 1000;
const MEDIA_UPLOAD_CLEANUP_GRACE_SECONDS = 60;
const MEDIA_UPLOAD_CLEANUP_BATCH_SIZE = 100;
const MEDIA_PURGE_RETRY_BATCH_SIZE = 100;
let syncEventLastRetentionPruneAt = 0;
let presenceLastPruneAt = 0;
let banterLastPruneAt = 0;
let realtimeLastPruneAt = 0;
let mediaUploadLastCleanupAt = 0;

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
        kind: "scroll" | "listen" | "huddle";
        host_subject_did_hash: string;
        status: "ACTIVE" | "ENDED";
        policy_pack_id?: string | null;
      }
    | undefined;
};

const ensureSyncSessionAccess = async (input: {
  sessionId: string;
  spaceId: string;
  expectedKind?: "scroll" | "listen" | "huddle";
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

const normalizeImageRefs = (imageRefs: string[]) => Array.from(new Set(imageRefs));

const validateOwnedImageRefs = async (input: {
  subjectDidHash: string;
  imageRefs: string[];
  spaceId?: string;
}) => {
  const dedupedRefs = normalizeImageRefs(input.imageRefs);
  if (dedupedRefs.length === 0) return { ok: true as const, imageRefs: dedupedRefs };
  if (dedupedRefs.length > MAX_POST_IMAGE_REFS) {
    return { ok: false as const, imageRefs: dedupedRefs };
  }
  const db = await getDb();
  const rows = await db.transaction(async (trx) => {
    return (await trx("social_media_assets")
      .whereIn("asset_id", dedupedRefs)
      .forUpdate()
      .select(
        "asset_id",
        "owner_subject_hash",
        "space_id",
        "status",
        "erased_at",
        "deleted_at",
        "finalized_at",
        "media_kind"
      )) as Array<{
      asset_id: string;
      owner_subject_hash: string;
      space_id: string | null;
      status: string;
      erased_at: string | null;
      deleted_at: string | null;
      finalized_at: string | null;
      media_kind: string;
    }>;
  });
  if (rows.length !== dedupedRefs.length) {
    return { ok: false as const, imageRefs: dedupedRefs };
  }
  for (const row of rows) {
    if (row.media_kind !== "image") return { ok: false as const, imageRefs: dedupedRefs };
    if (row.owner_subject_hash !== input.subjectDidHash) {
      return { ok: false as const, imageRefs: dedupedRefs };
    }
    if (row.status !== "ACTIVE" || !row.finalized_at || row.erased_at || row.deleted_at) {
      return { ok: false as const, imageRefs: dedupedRefs };
    }
    if (input.spaceId) {
      if (row.space_id !== input.spaceId) return { ok: false as const, imageRefs: dedupedRefs };
    } else if (row.space_id) {
      return { ok: false as const, imageRefs: dedupedRefs };
    }
  }
  return { ok: true as const, imageRefs: dedupedRefs };
};

const isMediaAssetViewable = (row: {
  status: string;
  finalized_at: string | null;
  erased_at: string | null;
  deleted_at: string | null;
  media_kind: string;
}) =>
  row.media_kind === "image" &&
  row.status === "ACTIVE" &&
  Boolean(row.finalized_at) &&
  !row.erased_at &&
  !row.deleted_at;

const checkMediaViewRateLimit = (bucketKey: string) => {
  const now = Date.now();
  const bucket = mediaViewBuckets.get(bucketKey);
  if (!bucket || now - bucket.startedAt >= MEDIA_VIEW_RATE_LIMIT_WINDOW_MS) {
    mediaViewBuckets.set(bucketKey, { count: 1, startedAt: now });
    return true;
  }
  if (bucket.count >= MEDIA_VIEW_RATE_LIMIT_MAX) return false;
  bucket.count += 1;
  return true;
};

const collectImageRefIds = (rows: Array<{ image_refs: unknown }>) => {
  const ids = new Set<string>();
  for (const row of rows) {
    const refs = Array.isArray(row.image_refs) ? row.image_refs : [];
    for (const ref of refs) {
      if (typeof ref === "string" && ref.length > 0) ids.add(ref);
    }
  }
  return Array.from(ids);
};

const loadViewableMediaAssetIds = async (assetIds: string[]) => {
  if (assetIds.length === 0) return new Set<string>();
  const rows = (await (await getDb())("social_media_assets")
    .whereIn("asset_id", assetIds)
    .andWhere({ status: "ACTIVE", media_kind: "image" })
    .whereNotNull("finalized_at")
    .whereNull("erased_at")
    .whereNull("deleted_at")
    .select("asset_id")) as Array<{ asset_id: string }>;
  return new Set(rows.map((row) => row.asset_id));
};

const redactPostImageRefs = async <
  T extends {
    image_refs: unknown;
  }
>(
  rows: T[]
) => {
  const viewableIds = await loadViewableMediaAssetIds(collectImageRefIds(rows));
  return rows.map((row) => {
    const originalRefs = Array.isArray(row.image_refs)
      ? row.image_refs.filter((value): value is string => typeof value === "string")
      : [];
    const redactedRefs = originalRefs.filter((value) => viewableIds.has(value));
    const redactedCount = originalRefs.length - redactedRefs.length;
    return {
      ...row,
      image_refs: redactedRefs,
      ...(redactedCount > 0
        ? { image_refs_redacted: true, image_refs_redacted_count: redactedCount }
        : {})
    };
  });
};

type PurgeDeleteEntry = {
  assetId: string;
  key: string | null | undefined;
};

const noteMediaPurgeAttempt = async (assetIds: string[], attemptedAt: string) => {
  if (assetIds.length === 0) return;
  const db = await getDb();
  const maxAttempts = config.MEDIA_PURGE_MAX_ATTEMPTS;
  await db("social_media_assets")
    .whereIn("asset_id", assetIds)
    .update({
      last_purge_attempt_at: attemptedAt,
      purge_attempt_count: db.raw("coalesce(purge_attempt_count, 0) + 1"),
      purge_dead_lettered_at: db.raw(
        "CASE WHEN purge_dead_lettered_at IS NULL AND coalesce(purge_attempt_count, 0) + 1 >= ? THEN ? ELSE purge_dead_lettered_at END",
        [maxAttempts, attemptedAt]
      ),
      purge_dead_letter_reason: db.raw(
        "CASE WHEN purge_dead_lettered_at IS NULL AND coalesce(purge_attempt_count, 0) + 1 >= ? THEN ? ELSE purge_dead_letter_reason END",
        [maxAttempts, "max_attempts_exceeded"]
      ),
      purge_pending: db.raw(
        "CASE WHEN coalesce(purge_attempt_count, 0) + 1 >= ? THEN false ELSE purge_pending END",
        [maxAttempts]
      )
    });
};

const markMediaAssetsPurgePending = async (assetIds: string[]) => {
  if (assetIds.length === 0) return;
  await (await getDb())("social_media_assets").whereIn("asset_id", assetIds).update({
    purge_pending: true
  });
};

const clearMediaAssetsPurgePending = async (assetIds: string[]) => {
  if (assetIds.length === 0) return;
  await (await getDb())("social_media_assets").whereIn("asset_id", assetIds).update({
    purge_pending: false
  });
};

const queueBestEffortMediaDelete = (
  entries: PurgeDeleteEntry[],
  options: { source: "cleanup" | "tombstone" | "retry" }
) => {
  const ownersByKey = new Map<string, Set<string>>();
  for (const entry of entries) {
    if (!entry.assetId || typeof entry.key !== "string" || entry.key.length === 0) continue;
    const owners = ownersByKey.get(entry.key) ?? new Set<string>();
    owners.add(entry.assetId);
    ownersByKey.set(entry.key, owners);
  }
  const keys = Array.from(ownersByKey.keys());
  if (keys.length === 0) return;
  void (async () => {
    const attemptedAt = new Date().toISOString();
    const attemptedAssetIds = Array.from(
      new Set(keys.flatMap((key) => Array.from(ownersByKey.get(key) ?? [])))
    );
    await noteMediaPurgeAttempt(attemptedAssetIds, attemptedAt);
    const settled = await Promise.allSettled(
      keys.map((key) => mediaStorageAdapter.deleteMediaObjects([key]))
    );
    const failedAssetIds = new Set<string>();
    const succeededAssetIds = new Set<string>();
    for (let index = 0; index < settled.length; index += 1) {
      const owners = ownersByKey.get(keys[index]) ?? new Set<string>();
      if (settled[index].status === "rejected") {
        for (const assetId of owners) failedAssetIds.add(assetId);
      } else {
        for (const assetId of owners) succeededAssetIds.add(assetId);
      }
    }
    if (succeededAssetIds.size > 0) {
      await clearMediaAssetsPurgePending(Array.from(succeededAssetIds));
    }
    if (failedAssetIds.size > 0) {
      await markMediaAssetsPurgePending(Array.from(failedAssetIds));
      log.warn("media_delete_best_effort_failed", {
        source: options.source,
        failedAssetCount: failedAssetIds.size
      });
    }
  })().catch((error) => {
    const detail = error instanceof Error ? error.message : String(error);
    log.warn("media_delete_best_effort_queue_error", {
      source: options.source,
      detail
    });
  });
};

const retryPendingMediaPurges = async (input: { ownerSubjectHash?: string } = {}) => {
  const db = await getDb();
  const rows = await db.transaction(async (trx) => {
    let query = trx("social_media_assets")
      .where({ purge_pending: true, media_kind: "image" })
      .whereNull("purge_dead_lettered_at")
      .whereNotNull("deleted_at");
    if (input.ownerSubjectHash) {
      query = query.andWhere({ owner_subject_hash: input.ownerSubjectHash });
    }
    return (await query
      .orderBy("last_purge_attempt_at", "asc")
      .orderBy("created_at", "asc")
      .limit(MEDIA_PURGE_RETRY_BATCH_SIZE)
      .forUpdate()
      .select("asset_id", "object_key", "thumbnail_object_key")) as Array<{
      asset_id: string;
      object_key: string | null;
      thumbnail_object_key: string | null;
    }>;
  });
  if (rows.length > 0) {
    queueBestEffortMediaDelete(
      rows.flatMap((row) => [
        { assetId: row.asset_id, key: row.object_key },
        { assetId: row.asset_id, key: row.thumbnail_object_key }
      ]),
      { source: "retry" }
    );
  }
};

export const maybeCleanupStaleUploads = async (
  input: { nowMs?: number; force?: boolean } = {}
): Promise<number> => {
  const nowMs = input.nowMs ?? Date.now();
  if (!input.force && nowMs - mediaUploadLastCleanupAt < MEDIA_UPLOAD_CLEANUP_INTERVAL_MS) {
    return 0;
  }
  mediaUploadLastCleanupAt = nowMs;
  const nowIso = new Date(nowMs).toISOString();
  await retryPendingMediaPurges();
  const staleCutoffIso = new Date(
    nowMs - (config.MEDIA_PRESIGN_TTL_SECONDS + MEDIA_UPLOAD_CLEANUP_GRACE_SECONDS) * 1000
  ).toISOString();
  const staleRows = await (await getDb()).transaction(async (trx) => {
    const pendingRows = (await trx("social_media_assets")
      .where({ status: "PENDING", media_kind: "image" })
      .whereNull("erased_at")
      .whereNull("deleted_at")
      .where("created_at", "<", staleCutoffIso)
      .orderBy("created_at", "asc")
      .limit(MEDIA_UPLOAD_CLEANUP_BATCH_SIZE)
      .forUpdate()
      .select("asset_id", "object_key", "thumbnail_object_key")) as Array<{
      asset_id: string;
      object_key: string | null;
      thumbnail_object_key: string | null;
    }>;
    if (!pendingRows.length) return [];
    await trx("social_media_assets")
      .whereIn(
        "asset_id",
        pendingRows.map((row) => row.asset_id)
      )
      .andWhere({ status: "PENDING" })
      .update({
        status: "ERASED",
        erased_at: nowIso,
        deleted_at: nowIso
      });
    return pendingRows;
  });
  if (staleRows.length > 0) {
    queueBestEffortMediaDelete(
      staleRows.flatMap((row) => [
        { assetId: row.asset_id, key: row.object_key },
        { assetId: row.asset_id, key: row.thumbnail_object_key }
      ]),
      { source: "cleanup" }
    );
  }
  return staleRows.length;
};

export const __setMediaUploadCleanupLastRunAtForTests = (value: number) => {
  mediaUploadLastCleanupAt = value;
};

const pruneExpiredPresenceRows = async () => {
  const nowMs = Date.now();
  if (nowMs - presenceLastPruneAt < 30_000) return;
  presenceLastPruneAt = nowMs;
  const ttlCutoff = new Date(nowMs - config.PRESENCE_PING_TTL_SECONDS * 1000).toISOString();
  const db = await getDb();
  await db("social_space_presence_pings").where("last_seen_at", "<", ttlCutoff).del();
  await db("presence_space_states").where("updated_at", "<", ttlCutoff).del();
};

const checkPresencePingRateLimit = (subjectDidHash: string, spaceId: string) => {
  const key = `${spaceId}:${subjectDidHash}`;
  const now = Date.now();
  const windowMs = config.PRESENCE_PING_RATE_WINDOW_SECONDS * 1000;
  const current = presencePingBuckets.get(key);
  if (!current || now - current.startedAt >= windowMs) {
    presencePingBuckets.set(key, { count: 1, startedAt: now });
    return true;
  }
  if (current.count >= config.PRESENCE_PING_RATE_MAX_PER_WINDOW) {
    return false;
  }
  current.count += 1;
  return true;
};

const getPresenceCounts = async (spaceId: string, activeCutoff: string) => {
  const rows = (await (
    await getDb()
  )("presence_space_states as states")
    .join("social_space_presence_pings as pings", function joinPresence() {
      this.on("states.space_id", "=", "pings.space_id").andOn(
        "states.subject_hash",
        "=",
        "pings.subject_hash"
      );
    })
    .where("states.space_id", spaceId)
    .andWhere("pings.last_seen_at", ">=", activeCutoff)
    .select("states.mode")
    .orderBy("states.updated_at", "desc")) as Array<{ mode: string }>;
  const counts = { quiet: 0, active: 0, immersive: 0 };
  for (const row of rows) {
    const mode = String(row.mode ?? "active");
    if (mode === "quiet") counts.quiet += 1;
    else if (mode === "immersive") counts.immersive += 1;
    else counts.active += 1;
  }
  return counts;
};

const getCrewById = async (crewId: string) =>
  (await (await getDb())("social_space_crews")
    .where({ crew_id: crewId })
    .whereNull("archived_at")
    .first()) as
    | {
        crew_id: string;
        space_id: string;
        name: string;
      }
    | undefined;

const isCrewCaptain = async (crewId: string, subjectHash: string) => {
  const row = await (await getDb())("social_space_crew_members")
    .where({ crew_id: crewId, subject_hash: subjectHash, role: "captain" })
    .whereNull("left_at")
    .first();
  return Boolean(row);
};

const isCrewMember = async (crewId: string, subjectHash: string) => {
  const row = await (await getDb())("social_space_crew_members")
    .where({ crew_id: crewId, subject_hash: subjectHash })
    .whereNull("left_at")
    .first();
  return Boolean(row);
};

type BanterThreadKind = "space_chat" | "challenge_chat" | "hangout_chat" | "crew_chat";
type BanterThreadRow = {
  thread_id: string;
  space_id: string;
  kind: BanterThreadKind;
  crew_id: string | null;
  challenge_id: string | null;
  hangout_session_id: string | null;
  created_at: string;
  updated_at: string;
  archived_at: string | null;
};

const getBanterThread = async (threadId: string) =>
  ((await (await getDb())("social_space_banter_threads")
    .where({ thread_id: threadId })
    .whereNull("archived_at")
    .first()) as BanterThreadRow | undefined) ?? null;

const mintBanterPermissionToken = async (input: { threadId: string; subjectHash: string }) => {
  const permissionId = randomUUID();
  const rawToken = randomBytes(32).toString("base64url");
  const permissionHash = hashHex(rawToken);
  const expiresAt = new Date(Date.now() + config.BANTER_PERMISSION_TTL_SECONDS * 1000).toISOString();
  await (
    await getDb()
  )("social_banter_permissions").insert({
    permission_id: permissionId,
    thread_id: input.threadId,
    subject_hash: input.subjectHash,
    permission_hash: permissionHash,
    expires_at: expiresAt,
    created_at: new Date().toISOString()
  });
  return { token: rawToken, expiresAt };
};

const mintRealtimePermissionToken = async (input: {
  subjectHash: string;
  channel: "presence" | "banter" | "hangout" | "challenge";
  spaceId: string;
  threadId?: string;
  sessionId?: string;
  challengeId?: string;
  canBroadcast: boolean;
}) => {
  const permissionId = randomUUID();
  const rawToken = randomBytes(32).toString("base64url");
  const permissionHash = hashHex(rawToken);
  const expiresAt = new Date(Date.now() + config.REALTIME_PERMISSION_TTL_SECONDS * 1000).toISOString();
  await (
    await getDb()
  )("social_realtime_permissions").insert({
    permission_id: permissionId,
    subject_hash: input.subjectHash,
    channel: input.channel,
    space_id: input.spaceId,
    thread_id: input.threadId ?? null,
    session_id: input.sessionId ?? null,
    challenge_id: input.challengeId ?? null,
    can_broadcast: input.canBroadcast,
    permission_hash: permissionHash,
    expires_at: expiresAt,
    created_at: new Date().toISOString()
  });
  return { token: rawToken, expiresAt };
};

const validateRealtimePermission = async (input: { permissionToken: string }) => {
  const permissionHash = hashHex(input.permissionToken);
  const row = await (await getDb())("social_realtime_permissions")
    .where({ permission_hash: permissionHash })
    .first();
  if (!row) return { ok: false as const, reason: "permission_invalid" };
  if (new Date(String(row.expires_at)).getTime() <= Date.now()) {
    return { ok: false as const, reason: "permission_expired" };
  }
  const privacy = await checkWriterPrivacy(String(row.subject_hash));
  if (privacy.restricted || privacy.tombstoned) {
    return { ok: false as const, reason: "privacy_restricted" };
  }
  return {
    ok: true as const,
    permission: {
      subjectHash: String(row.subject_hash),
      channel: String(row.channel),
      spaceId: String(row.space_id),
      threadId: row.thread_id ? String(row.thread_id) : null,
      sessionId: row.session_id ? String(row.session_id) : null,
      challengeId: row.challenge_id ? String(row.challenge_id) : null,
      canBroadcast: Boolean(row.can_broadcast)
    }
  };
};

const checkRealtimeBroadcastRate = (permissionHash: string) => {
  const now = Date.now();
  const windowMs = config.REALTIME_PUBLISH_RATE_WINDOW_SECONDS * 1000;
  const bucket = realtimeBroadcastBuckets.get(permissionHash);
  if (!bucket || now - bucket.startedAt >= windowMs) {
    realtimeBroadcastBuckets.set(permissionHash, { count: 1, startedAt: now });
    return true;
  }
  if (bucket.count >= config.REALTIME_PUBLISH_RATE_MAX_PER_WINDOW) {
    return false;
  }
  bucket.count += 1;
  return true;
};

const pruneRealtimeEvents = async () => {
  const now = Date.now();
  if (now - realtimeLastPruneAt < 60_000) return;
  realtimeLastPruneAt = now;
  const cutoff = new Date(now - config.REALTIME_EVENTS_RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString();
  await (await getDb())("social_realtime_events").where("created_at", "<", cutoff).del();
};

const publishRealtimeEvent = async (input: {
  channel: "presence" | "banter" | "hangout" | "challenge";
  spaceId: string;
  eventType: string;
  payload: Record<string, unknown>;
  threadId?: string | null;
  sessionId?: string | null;
  challengeId?: string | null;
}) => {
  await pruneRealtimeEvents().catch(() => undefined);
  const eventId = randomUUID();
  const createdAt = new Date().toISOString();
  const inserted = (await (
    await getDb()
  )("social_realtime_events")
    .insert({
      event_id: eventId,
      channel: input.channel,
      space_id: input.spaceId,
      thread_id: input.threadId ?? null,
      session_id: input.sessionId ?? null,
      challenge_id: input.challengeId ?? null,
      event_type: input.eventType,
      payload_json: input.payload,
      created_at: createdAt
    })
    .returning(["event_id", "created_at", "event_cursor"])) as Array<{
    event_id: string;
    created_at: string;
    event_cursor: string | number | bigint | null;
  }>;
  const row = inserted[0];
  return {
    eventId: row?.event_id ?? eventId,
    createdAt: row?.created_at ?? createdAt,
    cursor: row?.event_cursor === null || row?.event_cursor === undefined ? null : String(row.event_cursor)
  };
};

const validateBanterPermission = async (input: {
  threadId: string;
  subjectHash: string;
  permissionToken: string;
}) => {
  const permissionHash = hashHex(input.permissionToken);
  const row = await (await getDb())("social_banter_permissions")
    .where({ permission_hash: permissionHash, thread_id: input.threadId, subject_hash: input.subjectHash })
    .first();
  if (!row) return { ok: false as const, reason: "permission_invalid" };
  if (new Date(String(row.expires_at)).getTime() <= Date.now()) {
    return { ok: false as const, reason: "permission_expired" };
  }
  return { ok: true as const };
};

const pruneExpiredBanterRows = async () => {
  const nowMs = Date.now();
  if (nowMs - banterLastPruneAt < 30_000) return;
  banterLastPruneAt = nowMs;
  const db = await getDb();
  const messageCutoff = new Date(nowMs - config.BANTER_MESSAGE_RETENTION_DAYS * 24 * 60 * 60 * 1000)
    .toISOString();
  const statusCutoff = new Date(nowMs - config.BANTER_STATUS_TTL_SECONDS * 1000).toISOString();
  await db("social_banter_messages").where("created_at", "<", messageCutoff).del();
  await db("social_presence_status_messages").where("updated_at", "<", statusCutoff).del();
  await db("social_banter_permissions").where("expires_at", "<", new Date(nowMs).toISOString()).del();
};

const checkBanterRateLimit = (
  input: {
    subjectHash: string;
    threadId: string;
    socialTier: "bronze" | "silver" | "gold";
    moderator: boolean;
  }
) => {
  const key = `${input.threadId}:${input.subjectHash}`;
  const now = Date.now();
  const current = banterMessageBuckets.get(key);
  const windowMs = config.BANTER_RATE_WINDOW_SECONDS * 1000;
  const baseLimit =
    input.socialTier === "gold"
      ? config.BANTER_RATE_GOLD_PER_WINDOW
      : input.socialTier === "silver"
        ? config.BANTER_RATE_SILVER_PER_WINDOW
        : config.BANTER_RATE_BRONZE_PER_WINDOW;
  const limit = input.moderator ? Math.max(baseLimit, config.BANTER_RATE_GOLD_PER_WINDOW) : baseLimit;
  if (current?.cooldownUntil && now < current.cooldownUntil) {
    return { ok: false as const, reason: "cooldown" };
  }
  if (!current || now - current.startedAt >= windowMs) {
    banterMessageBuckets.set(key, { count: 1, startedAt: now });
    return { ok: true as const };
  }
  if (current.count >= limit) {
    current.cooldownUntil = now + config.BANTER_RATE_COOLDOWN_SECONDS * 1000;
    return { ok: false as const, reason: "rate_limited" };
  }
  current.count += 1;
  return { ok: true as const };
};

const startOfUtcDay = (input: Date) => {
  const next = new Date(input);
  next.setUTCHours(0, 0, 0, 0);
  return next;
};

const startOfUtcWeek = (input: Date) => {
  const day = input.getUTCDay();
  const diffToMonday = (day + 6) % 7;
  const next = startOfUtcDay(input);
  next.setUTCDate(next.getUTCDate() - diffToMonday);
  return next;
};

const applyStreakCompletion = async (input: {
  spaceId: string;
  subjectHash: string;
  streakType: "daily_challenge" | "weekly_challenge";
  completedAtIso: string;
}) => {
  const db = await getDb();
  const row = (await db("social_space_streaks")
    .where({
      space_id: input.spaceId,
      subject_hash: input.subjectHash,
      streak_type: input.streakType
    })
    .first()) as
    | {
        current_count: number;
        best_count: number;
        last_completed_at: string | null;
      }
    | undefined;
  const completedAt = new Date(input.completedAtIso);
  const boundary =
    input.streakType === "daily_challenge"
      ? startOfUtcDay(completedAt)
      : startOfUtcWeek(completedAt);
  let nextCurrent = 1;
  if (row?.last_completed_at) {
    const last = new Date(row.last_completed_at);
    const lastBoundary =
      input.streakType === "daily_challenge" ? startOfUtcDay(last) : startOfUtcWeek(last);
    if (lastBoundary.getTime() === boundary.getTime()) {
      nextCurrent = Number(row.current_count ?? 0);
    } else if (boundary.getTime() - lastBoundary.getTime() <= 8 * 24 * 60 * 60 * 1000) {
      nextCurrent = Number(row.current_count ?? 0) + 1;
    }
  }
  const best = Math.max(Number(row?.best_count ?? 0), nextCurrent);
  await db("social_space_streaks")
    .insert({
      space_id: input.spaceId,
      subject_hash: input.subjectHash,
      streak_type: input.streakType,
      current_count: nextCurrent,
      best_count: best,
      last_completed_at: input.completedAtIso,
      updated_at: input.completedAtIso
    })
    .onConflict(["space_id", "subject_hash", "streak_type"])
    .merge({
      current_count: nextCurrent,
      best_count: best,
      last_completed_at: input.completedAtIso,
      updated_at: input.completedAtIso
    });
};

const buildLeaderboard = async (spaceId: string, windowDays: number) => {
  const db = await getDb();
  const since = new Date(Date.now() - windowDays * 24 * 60 * 60 * 1000).toISOString();

  // Space leaderboard must be space-scoped (not global). We don't persist `space_id` on
  // `social_action_log`, so we scope by known space participants (members + profile settings).
  const participantHashes = new Set<string>();
  const membershipRows = (await db("social_space_memberships")
    .where({ space_id: spaceId })
    .whereIn("status", ["ACTIVE"])
    .select("subject_did_hash")) as Array<{ subject_did_hash: string }>;
  for (const row of membershipRows) participantHashes.add(String(row.subject_did_hash));
  const settingsRows = (await db("social_space_profile_settings")
    .where({ space_id: spaceId })
    .select("subject_hash")) as Array<{ subject_hash: string }>;
  for (const row of settingsRows) participantHashes.add(String(row.subject_hash));
  const participants = Array.from(participantHashes);
  if (participants.length === 0) {
    return [];
  }

  const signals = (await db("social_action_log")
    .whereIn("action_type", ["social.post.create", "social.reply.create", "ritual.complete"])
    .andWhere({ decision: "COMPLETE" })
    .andWhere("created_at", ">=", since)
    .whereNotNull("subject_did_hash")
    .whereIn("subject_did_hash", participants)
    .select("subject_did_hash", "action_type", "created_at")) as Array<{
    subject_did_hash: string;
    action_type: string;
    created_at: string;
  }>;
  const bySubject = new Map<
    string,
    { post: number; reply: number; ritual: number; activeDays: Set<string> }
  >();
  for (const row of signals) {
    const subject = String(row.subject_did_hash);
    const bucket = bySubject.get(subject) ?? {
      post: 0,
      reply: 0,
      ritual: 0,
      activeDays: new Set<string>()
    };
    if (row.action_type === "social.post.create") bucket.post += 1;
    else if (row.action_type === "social.reply.create") bucket.reply += 1;
    else if (row.action_type === "ritual.complete") bucket.ritual += 1;
    bucket.activeDays.add(String(row.created_at).slice(0, 10));
    bySubject.set(subject, bucket);
  }
  const rows: Array<{
    subjectHash: string;
    score: number;
    post: number;
    reply: number;
    ritual: number;
    activeDays: number;
  }> = [];
  for (const [subjectHash, bucket] of bySubject.entries()) {
    const postScore = Math.sqrt(Math.min(bucket.post, 20));
    const replyScore = Math.sqrt(Math.min(bucket.reply, 30));
    const ritualScore = 1.8 * Math.sqrt(Math.min(bucket.ritual, 14));
    const diversityWeight = 1 + Math.min(bucket.activeDays.size, 7) * 0.04;
    const score = Number(((postScore + replyScore + ritualScore) * diversityWeight).toFixed(4));
    rows.push({
      subjectHash,
      score,
      post: bucket.post,
      reply: bucket.reply,
      ritual: bucket.ritual,
      activeDays: bucket.activeDays.size
    });
  }
  rows.sort((a, b) => b.score - a.score);
  const topRows = rows.slice(0, config.LEADERBOARD_TOP_N * 3);
  const privacyCache = new Map<string, PrivacyStatus>();
  const optInRows = (await db("social_space_profile_settings")
    .where({ space_id: spaceId })
    .whereIn(
      "subject_hash",
      topRows.map((entry) => entry.subjectHash)
    )
    .select("subject_hash", "show_on_leaderboard", "presence_label")) as Array<{
    subject_hash: string;
    show_on_leaderboard: boolean;
    presence_label: string | null;
  }>;
  const optInByHash = new Map(
    optInRows.map((row) => [
      String(row.subject_hash),
      { show: Boolean(row.show_on_leaderboard), label: row.presence_label }
    ])
  );
  const profileRows = (await db("social_profiles")
    .whereIn(
      "subject_did_hash",
      topRows.map((entry) => entry.subjectHash)
    )
    .whereNull("deleted_at")
    .select("subject_did_hash", "display_name", "handle")) as Array<{
    subject_did_hash: string;
    display_name: string | null;
    handle: string | null;
  }>;
  const profileByHash = new Map(profileRows.map((row) => [String(row.subject_did_hash), row]));
  const output: Array<Record<string, unknown>> = [];
  for (const row of topRows) {
    let privacy = privacyCache.get(row.subjectHash);
    if (!privacy) {
      privacy = await getPrivacyStatus(row.subjectHash).catch(() => ({
        restricted: false,
        tombstoned: false
      }));
      privacyCache.set(row.subjectHash, privacy);
    }
    if (privacy.restricted || privacy.tombstoned) continue;
    const opt = optInByHash.get(row.subjectHash);
    const profile = profileByHash.get(row.subjectHash);
    output.push({
      score: row.score,
      signals: {
        post_success: row.post,
        reply_success: row.reply,
        ritual_complete: row.ritual,
        active_days: row.activeDays
      },
      identity:
        opt?.show && (opt.label || profile?.display_name || profile?.handle)
          ? {
              displayName:
                String(opt.label ?? "").trim() ||
                String(profile?.display_name ?? "").trim() ||
                String(profile?.handle ?? "").trim()
            }
          : { anonymous: true }
    });
    if (output.length >= config.LEADERBOARD_TOP_N) break;
  }
  return output;
};

type PulsePreferences = {
  enabled: boolean;
  notify_hangouts: boolean;
  notify_crews: boolean;
  notify_challenges: boolean;
  notify_rankings: boolean;
  notify_streaks: boolean;
};

type PulseCard = {
  type: "crew_active" | "hangout_live" | "challenge_ending" | "streak_risk" | "rank_up";
  title: string;
  value: string | number;
  cta: string;
  explain: string;
  route:
    | "open_crews"
    | "join_hangout"
    | "open_challenges"
    | "complete_challenge"
    | "open_rankings"
    | "compose_post";
  sessionId?: string;
  challengeId?: string;
};

const defaultPulsePreferences: PulsePreferences = {
  enabled: true,
  notify_hangouts: true,
  notify_crews: true,
  notify_challenges: true,
  notify_rankings: true,
  notify_streaks: true
};

const toPulsePreferencesResponse = (prefs: PulsePreferences) => ({
  enabled: prefs.enabled,
  notifyHangouts: prefs.notify_hangouts,
  notifyCrews: prefs.notify_crews,
  notifyChallenges: prefs.notify_challenges,
  notifyRankings: prefs.notify_rankings,
  notifyStreaks: prefs.notify_streaks
});

const getPulsePreferences = async (
  spaceId: string,
  subjectHash: string | null
): Promise<PulsePreferences> => {
  if (!subjectHash) return defaultPulsePreferences;
  const row = (await (await getDb())("social_space_pulse_preferences")
    .where({ space_id: spaceId, subject_hash: subjectHash })
    .first()) as Partial<PulsePreferences> | undefined;
  if (!row) return defaultPulsePreferences;
  return {
    enabled: Boolean(row.enabled),
    notify_hangouts: Boolean(row.notify_hangouts),
    notify_crews: Boolean(row.notify_crews),
    notify_challenges: Boolean(row.notify_challenges),
    notify_rankings: Boolean(row.notify_rankings),
    notify_streaks: Boolean(row.notify_streaks)
  };
};

const upsertPulsePreferences = async (
  spaceId: string,
  subjectHash: string,
  next: PulsePreferences
) => {
  const now = new Date().toISOString();
  await (
    await getDb()
  )("social_space_pulse_preferences")
    .insert({
      space_id: spaceId,
      subject_hash: subjectHash,
      ...next,
      updated_at: now
    })
    .onConflict(["space_id", "subject_hash"])
    .merge({ ...next, updated_at: now });
};

const formatMinutesUntil = (isoTime: string) => {
  const deltaMs = Math.max(0, new Date(isoTime).getTime() - Date.now());
  const minutes = Math.max(1, Math.ceil(deltaMs / 60_000));
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  const remainder = minutes % 60;
  return remainder > 0 ? `${hours}h ${remainder}m` : `${hours}h`;
};

const buildPulseCards = async (input: {
  spaceId: string;
  subjectHash: string | null;
  preferences: PulsePreferences;
}): Promise<PulseCard[]> => {
  if (!input.preferences.enabled) return [];
  const db = await getDb();
  const now = new Date();
  const nowIso = now.toISOString();
  const cards: PulseCard[] = [];

  if (input.preferences.notify_crews && input.subjectHash) {
    const viewerCrews = (await db("social_space_crew_members as members")
      .join("social_space_crews as crews", "members.crew_id", "crews.crew_id")
      .where({
        "members.subject_hash": input.subjectHash,
        "crews.space_id": input.spaceId
      })
      .whereNull("members.left_at")
      .whereNull("crews.archived_at")
      .select("members.crew_id")) as Array<{ crew_id: string }>;
    const crewIds = viewerCrews.map((row) => row.crew_id);
    if (crewIds.length > 0) {
      const cutoff = new Date(Date.now() - config.PRESENCE_PING_TTL_SECONDS * 1000).toISOString();
      const activeCrewRow = await db("social_space_crew_members as members")
        .join("social_space_presence_pings as pings", function joinCrewPulsePresence() {
          this.on("members.subject_hash", "=", "pings.subject_hash");
        })
        .whereIn("members.crew_id", crewIds)
        .whereNull("members.left_at")
        .andWhere("pings.space_id", input.spaceId)
        .andWhere("pings.last_seen_at", ">=", cutoff)
        .countDistinct<{ count: string }>("members.subject_hash as count")
        .first();
      const activeCount = Number(activeCrewRow?.count ?? 0);
      if (activeCount > 0) {
        cards.push({
          type: "crew_active",
          title: "Your crew is active",
          value: activeCount,
          cta: "Open Crew",
          explain:
            "Crew activity uses recent presence pings from members in your active crews for this space.",
          route: "open_crews"
        });
      }
    }
  }

  if (input.preferences.notify_hangouts) {
    const hangoutRow = (await db("sync_sessions")
      .where({ space_id: input.spaceId, kind: "huddle", status: "ACTIVE" })
      .orderBy("created_at", "desc")
      .first()) as { session_id: string } | undefined;
    if (hangoutRow?.session_id) {
      const countRow = await db("sync_sessions")
        .where({ space_id: input.spaceId, kind: "huddle", status: "ACTIVE" })
        .count<{ count: string }>("session_id as count")
        .first();
      cards.push({
        type: "hangout_live",
        title: "Hangout live now",
        value: Number(countRow?.count ?? 1),
        cta: "Join Hangout",
        explain: "A hangout is live when its control-plane session is active in this space.",
        route: "join_hangout",
        sessionId: hangoutRow.session_id
      });
    }
  }

  if (input.preferences.notify_challenges) {
    const soonCutoffIso = new Date(
      Date.now() + config.PULSE_CHALLENGE_ENDING_SOON_SECONDS * 1000
    ).toISOString();
    const endingChallenge = (await db("social_space_challenges")
      .where({ space_id: input.spaceId, status: "ACTIVE" })
      .andWhere("ends_at", ">", nowIso)
      .andWhere("ends_at", "<=", soonCutoffIso)
      .orderBy("ends_at", "asc")
      .first()) as { challenge_id: string; ends_at: string } | undefined;
    if (endingChallenge) {
      cards.push({
        type: "challenge_ending",
        title: "Challenge ends soon",
        value: formatMinutesUntil(endingChallenge.ends_at),
        cta: "Open Challenge",
        explain: "Ending-soon highlights active challenges that close within your pulse window.",
        route: "open_challenges",
        challengeId: endingChallenge.challenge_id
      });
    }
  }

  if (input.preferences.notify_streaks && input.subjectHash) {
    const streak = (await db("social_space_streaks")
      .where({
        space_id: input.spaceId,
        subject_hash: input.subjectHash,
        streak_type: "daily_challenge"
      })
      .first()) as { current_count: number } | undefined;
    if (Number(streak?.current_count ?? 0) > 0) {
      const startTodayIso = startOfUtcDay(now).toISOString();
      const completedToday = await db("social_space_challenge_participation as participation")
        .join(
          "social_space_challenges as challenges",
          "participation.challenge_id",
          "challenges.challenge_id"
        )
        .where({
          "participation.subject_hash": input.subjectHash,
          "challenges.space_id": input.spaceId,
          "challenges.cadence": "daily"
        })
        .whereNotNull("participation.completed_at")
        .andWhere("participation.completed_at", ">=", startTodayIso)
        .first();
      if (!completedToday) {
        cards.push({
          type: "streak_risk",
          title: "Streak at risk",
          value: "Daily streak",
          cta: "Complete Challenge",
          explain: "Your daily challenge streak has no completion logged yet for today.",
          route: "complete_challenge"
        });
      }
    }
  }

  if (input.preferences.notify_rankings && input.subjectHash) {
    const sinceIso = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const postRows = (await db("social_space_posts")
      .where({ space_id: input.spaceId })
      .whereNull("deleted_at")
      .andWhere("created_at", ">=", sinceIso)
      .select("author_subject_did_hash")) as Array<{ author_subject_did_hash: string }>;
    const challengeRows = (await db("social_space_challenge_participation as participation")
      .join(
        "social_space_challenges as challenges",
        "participation.challenge_id",
        "challenges.challenge_id"
      )
      .where({ "challenges.space_id": input.spaceId })
      .whereNotNull("participation.completed_at")
      .andWhere("participation.completed_at", ">=", sinceIso)
      .select("participation.subject_hash")) as Array<{ subject_hash: string }>;
    const ritualRows = (await db("social_space_ritual_participants as participants")
      .join("social_space_rituals as rituals", "participants.ritual_id", "rituals.ritual_id")
      .where({ "rituals.space_id": input.spaceId })
      .whereNotNull("participants.completed_at")
      .andWhere("participants.completed_at", ">=", sinceIso)
      .select("participants.subject_hash")) as Array<{ subject_hash: string }>;
    const scoreBySubject = new Map<string, number>();
    const addScore = (subject: string, amount: number) => {
      scoreBySubject.set(subject, (scoreBySubject.get(subject) ?? 0) + amount);
    };
    for (const row of postRows) addScore(String(row.author_subject_did_hash), 1);
    for (const row of challengeRows) addScore(String(row.subject_hash), 1);
    for (const row of ritualRows) addScore(String(row.subject_hash), 1);
    const ranked = [...scoreBySubject.entries()]
      .map(([subject, score]) => ({ subject, score }))
      .sort((a, b) => b.score - a.score);
    const viewerIndex = ranked.findIndex((entry) => entry.subject === input.subjectHash);
    if (viewerIndex > 0) {
      const ahead = ranked[viewerIndex - 1];
      const viewer = ranked[viewerIndex];
      const scoreGap = Math.max(0, Number(ahead.score) - Number(viewer.score));
      if (scoreGap <= config.PULSE_RANK_NEAR_GAP) {
        cards.push({
          type: "rank_up",
          title: `${scoreGap} away from rank up`,
          value: "Top Contributors",
          cta: "View Rankings",
          explain:
            "Rank-up compares your recent verified actions in this space against the next contributor slot.",
          route: "open_rankings"
        });
      }
    }
  }

  return cards;
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
  const url = new URL("/v1/admin/privacy/status", config.ISSUER_SERVICE_BASE_URL);
  url.searchParams.set("subjectDidHash", subjectDidHash);
  const controller = new AbortController();
  const timeout = setTimeout(() => {
    controller.abort("issuer_privacy_status_timeout");
  }, config.ISSUER_PRIVACY_STATUS_TIMEOUT_MS);
  timeout.unref?.();
  let timedOut = false;
  controller.signal.addEventListener(
    "abort",
    () => {
      if (controller.signal.reason === "issuer_privacy_status_timeout") {
        timedOut = true;
      }
    },
    { once: true }
  );
  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
      signal: controller.signal
    });
  } catch (error) {
    if (timedOut) {
      throw new Error("issuer_privacy_status_timeout");
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
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
  const erasedSubjectHash = hashHex(`erased:${subjectDidHash}`);
  const mediaRows = (await db("social_media_assets")
    .where({ owner_subject_hash: subjectDidHash })
    .whereNull("erased_at")
    .select("asset_id", "object_key", "thumbnail_object_key")) as Array<{
    asset_id: string;
    object_key: string | null;
    thumbnail_object_key: string | null;
  }>;
  await db.transaction(async (trx) => {
    await trx("social_profiles")
      .where({ subject_did_hash: subjectDidHash })
      .whereNull("deleted_at")
      .update({ deleted_at: now, updated_at: now, bio: null });
    await trx("social_posts")
      .where({ author_subject_did_hash: subjectDidHash })
      .whereNull("deleted_at")
      .update({ deleted_at: now, content_text: "[erased]" });
    await trx("social_space_posts")
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
      .update({ owner_subject_hash: erasedSubjectHash, published_at: null });
    await trx("media_sound_assets")
      .where({ creator_subject_hash: subjectDidHash })
      .update({ creator_subject_hash: erasedSubjectHash });
    await trx("media_soundpacks")
      .where({ owner_subject_hash: subjectDidHash })
      .update({ owner_subject_hash: erasedSubjectHash, published_at: null });
    await trx("media_soundpack_activations")
      .where({ activated_by_subject_hash: subjectDidHash })
      .update({ activated_by_subject_hash: erasedSubjectHash, deactivated_at: now });
    await trx("presence_space_states").where({ subject_hash: subjectDidHash }).del();
    await trx("social_space_presence_pings").where({ subject_hash: subjectDidHash }).del();
    await trx("social_space_profile_settings").where({ subject_hash: subjectDidHash }).del();
    await trx("social_spaces")
      .where({ created_by_subject_did_hash: subjectDidHash })
      .update({ created_by_subject_did_hash: erasedSubjectHash });
    await trx("social_space_memberships")
      .where({ subject_did_hash: subjectDidHash })
      .update({ subject_did_hash: erasedSubjectHash, status: "LEFT", left_at: now });
    await trx("presence_invite_events")
      .where({ inviter_hash: subjectDidHash })
      .update({ inviter_hash: erasedSubjectHash, status: "ERASED" });
    await trx("presence_invite_events")
      .where({ invitee_hash: subjectDidHash })
      .update({ invitee_hash: erasedSubjectHash, status: "ERASED" });
    await trx("sync_watch_sessions")
      .where({ host_hash: subjectDidHash })
      .update({ host_hash: erasedSubjectHash, status: "ENDED", ended_at: now });
    await trx("sync_watch_participants")
      .where({ subject_hash: subjectDidHash })
      .update({ left_at: now });
    await trx("sync_sessions")
      .where({ host_subject_did_hash: subjectDidHash })
      .update({
        host_subject_did_hash: erasedSubjectHash,
        status: db.raw("CASE WHEN status = ? THEN ? ELSE status END", ["ACTIVE", "ENDED"]),
        ended_at: db.raw("CASE WHEN ended_at IS NULL THEN ? ELSE ended_at END", [now])
      });
    await trx("sync_session_participants")
      .where({ subject_did_hash: subjectDidHash })
      .whereNull("left_at")
      .update({ left_at: now });
    await trx("sync_session_permissions").where({ subject_did_hash: subjectDidHash }).del();
    await trx("sync_session_events")
      .where({ actor_subject_did_hash: subjectDidHash })
      .update({
        actor_subject_did_hash: erasedSubjectHash
      });
    await trx("sync_session_reports")
      .where({ reporter_subject_did_hash: subjectDidHash })
      .update({
        reporter_subject_did_hash: erasedSubjectHash
      });
    await trx("social_reports")
      .where({ reporter_subject_did_hash: subjectDidHash })
      .update({ reporter_subject_did_hash: erasedSubjectHash });
    await trx("social_action_log")
      .where({ subject_did_hash: subjectDidHash })
      .update({ subject_did_hash: erasedSubjectHash });
    await trx("social_actions_log")
      .where({ subject_did_hash: subjectDidHash })
      .update({ subject_did_hash: erasedSubjectHash });
    await trx("social_space_ritual_participants").where({ subject_hash: subjectDidHash }).del();
    await trx("social_space_rituals")
      .where({ created_by_subject_hash: subjectDidHash })
      .update({
        created_by_subject_hash: erasedSubjectHash,
        status: db.raw("CASE WHEN status = ? THEN ? ELSE status END", ["ACTIVE", "ENDED"]),
        closed_at: db.raw("CASE WHEN closed_at IS NULL THEN ? ELSE closed_at END", [now])
      });
    await trx("social_space_crew_members").where({ subject_hash: subjectDidHash }).del();
    await trx("social_space_crews")
      .where({ created_by_subject_hash: subjectDidHash })
      .update({ created_by_subject_hash: erasedSubjectHash, archived_at: now });
    await trx("social_space_challenge_participation").where({ subject_hash: subjectDidHash }).del();
    await trx("social_space_challenges")
      .where({ created_by_subject_hash: subjectDidHash })
      .update({
        created_by_subject_hash: erasedSubjectHash,
        status: db.raw("CASE WHEN status = ? THEN ? ELSE status END", ["ACTIVE", "ENDED"]),
        ended_at: db.raw("CASE WHEN ended_at IS NULL THEN ? ELSE ended_at END", [now])
      });
    await trx("social_space_streaks").where({ subject_hash: subjectDidHash }).del();
    await trx("social_space_pulse_preferences").where({ subject_hash: subjectDidHash }).del();
    await trx("social_space_member_restrictions")
      .where({ subject_did_hash: subjectDidHash })
      .update({ subject_did_hash: erasedSubjectHash });
    await trx("social_space_moderation_actions")
      .where({ moderator_subject_did_hash: subjectDidHash })
      .update({ moderator_subject_did_hash: erasedSubjectHash });
    await trx("social_space_moderation_actions")
      .where({ target_subject_did_hash: subjectDidHash })
      .update({ target_subject_did_hash: erasedSubjectHash });
    await trx("social_banter_messages")
      .where({ author_subject_hash: subjectDidHash })
      .update({
        body_text: null,
        visibility: "tombstoned",
        deleted_at: now
      });
    await trx("social_presence_status_messages").where({ subject_hash: subjectDidHash }).del();
    await trx("social_banter_reactions").where({ reactor_subject_hash: subjectDidHash }).del();
    await trx("social_banter_permissions").where({ subject_hash: subjectDidHash }).del();
    await trx("social_realtime_permissions").where({ subject_hash: subjectDidHash }).del();
    await trx("social_media_assets")
      .where({ owner_subject_hash: subjectDidHash })
      .update({ status: "ERASED", erased_at: now, deleted_at: now });
  });
  queueBestEffortMediaDelete(
    mediaRows.flatMap((row) => [
      { assetId: row.asset_id, key: row.object_key },
      { assetId: row.asset_id, key: row.thumbnail_object_key }
    ]),
    { source: "tombstone" }
  );
  await retryPendingMediaPurges({ ownerSubjectHash: subjectDidHash });
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

const getFlowThresholdTier = (strict: boolean) => {
  const configured = strict
    ? (process.env.SOCIAL_FLOW_STRICT_MIN_TRUST_TIER ?? "silver")
    : (process.env.SOCIAL_FLOW_MIN_TRUST_TIER ?? "bronze");
  return normalizeTier(configured);
};

const getSpaceFlowThresholdTier = (strict: boolean) => {
  const configured = strict
    ? (process.env.SOCIAL_SPACE_FLOW_STRICT_MIN_TRUST_TIER ?? "silver")
    : (process.env.SOCIAL_SPACE_FLOW_MIN_TRUST_TIER ?? "bronze");
  return normalizeTier(configured);
};

const getFlowAntiGaming = async () => {
  const db = await getDb();
  // Data-driven: derive anti-gaming parameters from enabled Aura rules, not seeded rule IDs.
  const rows = (await db("aura_rules")
    .where({ enabled: true })
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
      return reply.code(503).send(
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
      return reply.code(503).send(
        makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
          devMode: config.DEV_MODE
        })
      );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const imageValidation = await validateOwnedImageRefs({
      subjectDidHash,
      imageRefs: body.imageRefs
    });
    if (!imageValidation.ok) {
      return reply.code(400).send(
        makeErrorResponse("invalid_request", "One or more image refs are invalid for this post", {
          devMode: config.DEV_MODE
        })
      );
    }

    const postId = randomUUID();
    const now = new Date().toISOString();
    await (
      await getDb()
    )("social_posts").insert({
      post_id: postId,
      author_subject_did_hash: subjectDidHash,
      content_text: body.content,
      content_hash: hashHex(body.content),
      image_refs: imageValidation.imageRefs,
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
      return reply.code(503).send(
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
      return reply.code(503).send(
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
      return reply.code(503).send(
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
      return reply.code(503).send(
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
      return reply.code(503).send(
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
      return reply.code(503).send(
        makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
          devMode: config.DEV_MODE
        })
      );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const imageValidation = await validateOwnedImageRefs({
      subjectDidHash,
      imageRefs: body.imageRefs,
      spaceId: body.spaceId
    });
    if (!imageValidation.ok) {
      return reply.code(400).send(
        makeErrorResponse("invalid_request", "One or more image refs are invalid for this post", {
          devMode: config.DEV_MODE
        })
      );
    }

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
      image_refs: imageValidation.imageRefs,
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
      return reply.code(503).send(
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
    const redactedRows = await redactPostImageRefs(rows as Array<{ image_refs: unknown }>);
    const redactedById = new Map(
      redactedRows.map((row) => [String((row as { space_post_id?: string }).space_post_id ?? ""), row])
    );
    const privacyCache = new Map<string, PrivacyStatus>();
    const posts: Array<Record<string, unknown>> = [];
    for (const row of rows) {
      const redactedRow = redactedById.get(String(row.space_post_id));
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
        image_refs: Array.isArray(redactedRow?.image_refs) ? redactedRow.image_refs : [],
        ...(redactedRow?.image_refs_redacted_count
          ? {
              image_refs_redacted: true,
              image_refs_redacted_count: redactedRow.image_refs_redacted_count
            }
          : {}),
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
    void postRequirements;
    const minTier = getSpaceFlowThresholdTier(query.safety === "strict");
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
    const flowRows = diversified.map((entry) => ({
      space_post_id: entry.row.space_post_id,
      content_text: entry.row.content_text,
      content_hash: entry.row.content_hash,
      image_refs: Array.isArray(entry.row.image_refs) ? entry.row.image_refs : [],
      created_at: entry.row.created_at,
      trust_stamps: [tierLabel(entry.tier)],
      explain_available: true
    }));
    const posts = await redactPostImageRefs(flowRows);
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
        // Customer-ready, data-driven: surface policy requirements (labels) instead of hardcoded tier thresholds.
        join: joinRequirements.map((r) => r.label),
        post: postRequirements.map((r) => r.label),
        moderate: moderateRequirements.map((r) => r.label)
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
        trust_floor: { join: null, post: null, moderate: null },
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
      trust_floor: { join: null, post: null, moderate: null },
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
      return reply.code(503).send(
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
        return reply.code(503).send(
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
      return reply.code(503).send(
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

  app.get("/v1/social/spaces/:spaceId/leaderboard", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const { spaceId } = spaceParamsSchema.parse(request.params ?? {});
    const query = leaderboardQuerySchema.parse(request.query ?? {});
    const space = await getSpaceById(spaceId);
    if (!space) {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Space not found"));
    }
    const windowDays = query.window === "14d" ? 14 : 7;
    const topContributors = await buildLeaderboard(spaceId, windowDays);
    return reply.send({
      space_id: spaceId,
      window: query.window,
      top_contributors: topContributors,
      explain: "Ranked by verified contributions, not likes."
    });
  });

  app.get("/v1/social/spaces/:spaceId/rankings", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const { spaceId } = spaceParamsSchema.parse(request.params ?? {});
    const query = rankingsQuerySchema.parse(request.query ?? {});
    const space = await getSpaceById(spaceId);
    if (!space) {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Space not found"));
    }
    if (query.type === "contributors") {
      const topContributors = await buildLeaderboard(spaceId, 7);
      return reply.send({
        space_id: spaceId,
        type: "contributors",
        title: "Top Contributors this week",
        rows: topContributors
      });
    }
    const rows = (await (await getDb())("social_space_streaks")
      .where({ space_id: spaceId })
      .orderBy("current_count", "desc")
      .limit(config.LEADERBOARD_TOP_N)
      .select("subject_hash", "streak_type", "current_count", "best_count")) as Array<{
      subject_hash: string;
      streak_type: string;
      current_count: number;
      best_count: number;
    }>;
    return reply.send({
      space_id: spaceId,
      type: "streaks",
      title: "Top Streaks",
      rows: rows.map((row) => ({
        streak_type: row.streak_type,
        current_count: Number(row.current_count ?? 0),
        best_count: Number(row.best_count ?? 0)
      }))
    });
  });

  app.post("/v1/social/spaces/:spaceId/crews", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const { spaceId } = spaceParamsSchema.parse(request.params ?? {});
    const body = crewCreateSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    if (!(await hasActiveSpaceMembership(spaceId, subjectDidHash))) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", "Space membership required"));
    }
    let gate = await verifyAndGate({
      subjectDidHash,
      actionId: "social.crew.create",
      actionType: "crew_create",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: spaceId }
    }).catch(() => null);
    if (gate?.denied) {
      gate = await verifyAndGate({
        subjectDidHash,
        actionId: "social.space.moderate",
        actionType: "crew_create",
        presentation: body.presentation,
        nonce: body.nonce,
        audience: body.audience,
        context: { space_id: spaceId }
      }).catch(() => null);
    }
    if (!gate) {
      return reply
        .code(503)
        .send(makeErrorResponse("requirements_unavailable", "Requirements unavailable"));
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const crewId = randomUUID();
    const now = new Date().toISOString();
    const db = await getDb();
    await db.transaction(async (trx) => {
      await trx("social_space_crews").insert({
        crew_id: crewId,
        space_id: spaceId,
        name: body.name,
        created_by_subject_hash: subjectDidHash,
        created_at: now
      });
      await trx("social_space_crew_members").insert({
        crew_id: crewId,
        subject_hash: subjectDidHash,
        role: "captain",
        joined_at: now
      });
    });
    incCompleted("crew_create");
    return reply.send({ decision: "ALLOW", crewId });
  });

  app.get("/v1/social/spaces/:spaceId/crews", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const { spaceId } = spaceParamsSchema.parse(request.params ?? {});
    const rows = (await (await getDb())("social_space_crews")
      .where({ space_id: spaceId })
      .whereNull("archived_at")
      .orderBy("created_at", "desc")
      .select("crew_id", "name", "created_at")) as Array<{
      crew_id: string;
      name: string;
      created_at: string;
    }>;
    const crewIds = rows.map((row) => row.crew_id);
    const memberCountRowsRaw =
      crewIds.length === 0
        ? []
        : await (await getDb())("social_space_crew_members")
            .whereIn("crew_id", crewIds)
            .whereNull("left_at")
            .groupBy("crew_id")
            .select("crew_id")
            .count<{ crew_id: string; count: string }>("crew_id as count");
    const memberCountRows = memberCountRowsRaw as unknown as Array<{
      crew_id: string;
      count: string;
    }>;
    const memberCounts =
      crewIds.length === 0
        ? new Map<string, number>()
        : new Map(memberCountRows.map((entry) => [entry.crew_id, Number(entry.count ?? 0)]));
    return reply.send({
      space_id: spaceId,
      crews: rows.map((row) => ({
        crew_id: row.crew_id,
        name: row.name,
        member_count: memberCounts.get(row.crew_id) ?? 0,
        created_at: row.created_at
      }))
    });
  });

  app.post("/v1/social/crews/:crewId/join", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const params = z.object({ crewId: z.string().uuid() }).parse(request.params ?? {});
    const body = crewJoinSchema.parse(request.body ?? {});
    const crew = await getCrewById(params.crewId);
    if (!crew) return reply.code(404).send(makeErrorResponse("invalid_request", "Crew not found"));
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    if (!(await hasActiveSpaceMembership(crew.space_id, subjectDidHash))) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", "Space membership required"));
    }
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "social.crew.join",
      actionType: "crew_join",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: crew.space_id }
    }).catch(() => null);
    if (!gate) {
      return reply
        .code(503)
        .send(makeErrorResponse("requirements_unavailable", "Requirements unavailable"));
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    await (
      await getDb()
    )("social_space_crew_members")
      .insert({
        crew_id: params.crewId,
        subject_hash: subjectDidHash,
        role: "member",
        joined_at: new Date().toISOString(),
        left_at: null
      })
      .onConflict(["crew_id", "subject_hash"])
      .merge({ left_at: null, joined_at: new Date().toISOString() });
    incCompleted("crew_join");
    return reply.send({ decision: "ALLOW" });
  });

  app.post("/v1/social/crews/:crewId/invite", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const params = z.object({ crewId: z.string().uuid() }).parse(request.params ?? {});
    const body = crewInviteSchema.parse(request.body ?? {});
    const crew = await getCrewById(params.crewId);
    if (!crew) return reply.code(404).send(makeErrorResponse("invalid_request", "Crew not found"));
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const inviteeHash = pseudonymizer.didToHash(body.inviteeDid);
    if (!(await hasActiveSpaceMembership(crew.space_id, subjectDidHash))) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", "Space membership required"));
    }
    const captain = await isCrewCaptain(params.crewId, subjectDidHash);
    let gate = await verifyAndGate({
      subjectDidHash,
      actionId: "social.crew.invite",
      actionType: "crew_invite",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: crew.space_id }
    }).catch(() => null);
    let moderatorOverride = false;
    if (gate?.denied) {
      gate = await verifyAndGate({
        subjectDidHash,
        actionId: "social.space.moderate",
        actionType: "crew_invite",
        presentation: body.presentation,
        nonce: body.nonce,
        audience: body.audience,
        context: { space_id: crew.space_id }
      }).catch(() => null);
      moderatorOverride = Boolean(gate && !gate.denied);
    }
    if (!gate) {
      return reply
        .code(503)
        .send(makeErrorResponse("requirements_unavailable", "Requirements unavailable"));
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    if (!captain && !moderatorOverride) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", "Captain or moderator required"));
    }
    if (!(await hasActiveSpaceMembership(crew.space_id, inviteeHash))) {
      return reply
        .code(409)
        .send(makeErrorResponse("invalid_request", "Invitee must join space first"));
    }
    await (
      await getDb()
    )("social_space_crew_members")
      .insert({
        crew_id: params.crewId,
        subject_hash: inviteeHash,
        role: "member",
        joined_at: new Date().toISOString(),
        left_at: null
      })
      .onConflict(["crew_id", "subject_hash"])
      .merge({ left_at: null, joined_at: new Date().toISOString() });
    incCompleted("crew_invite");
    return reply.send({ decision: "ALLOW" });
  });

  app.post("/v1/social/crews/:crewId/leave", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const params = z.object({ crewId: z.string().uuid() }).parse(request.params ?? {});
    const body = crewLeaveSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const updated = await (await getDb())("social_space_crew_members")
      .where({ crew_id: params.crewId, subject_hash: subjectDidHash })
      .whereNull("left_at")
      .update({ left_at: new Date().toISOString() });
    if (!updated) {
      return reply
        .code(404)
        .send(makeErrorResponse("invalid_request", "Crew membership not found"));
    }
    incCompleted("crew_leave");
    return reply.send({ decision: "ALLOW" });
  });

  app.get("/v1/social/crews/:crewId/presence", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const params = z.object({ crewId: z.string().uuid() }).parse(request.params ?? {});
    const query = crewPresenceQuerySchema.parse(request.query ?? {});
    const crew = await getCrewById(params.crewId);
    if (!crew) return reply.code(404).send(makeErrorResponse("invalid_request", "Crew not found"));
    const cutoff = new Date(Date.now() - config.PRESENCE_PING_TTL_SECONDS * 1000).toISOString();
    const activeRows = (await (
      await getDb()
    )("social_space_crew_members as members")
      .join("social_space_presence_pings as pings", function joinCrewPresence() {
        this.on("members.subject_hash", "=", "pings.subject_hash");
      })
      .where({ "members.crew_id": params.crewId })
      .andWhere("pings.space_id", crew.space_id)
      .whereNull("members.left_at")
      .andWhere("pings.last_seen_at", ">=", cutoff)
      .count<{ count: string }>("members.subject_hash as count")
      .first()) as { count: string } | undefined;
    let yourActive = false;
    if (query.subjectDid) {
      const viewerHash = pseudonymizer.didToHash(query.subjectDid);
      const row = await (
        await getDb()
      )("social_space_crew_members as members")
        .join("social_space_presence_pings as pings", function joinSelfPresence() {
          this.on("members.subject_hash", "=", "pings.subject_hash");
        })
        .where({ "members.crew_id": params.crewId, "members.subject_hash": viewerHash })
        .andWhere("pings.space_id", crew.space_id)
        .whereNull("members.left_at")
        .andWhere("pings.last_seen_at", ">=", cutoff)
        .first();
      yourActive = Boolean(row);
    }
    return reply.send({
      crew_id: params.crewId,
      active_count: Number(activeRows?.count ?? 0),
      you: { active: yourActive }
    });
  });

  app.get("/v1/social/spaces/:spaceId/challenges", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const { spaceId } = spaceParamsSchema.parse(request.params ?? {});
    const now = new Date().toISOString();
    const rows = (await (await getDb())("social_space_challenges")
      .where({ space_id: spaceId })
      .whereIn("status", ["ACTIVE"])
      .andWhere("ends_at", ">", now)
      .orderBy("starts_at", "asc")
      .select("challenge_id", "cadence", "title", "starts_at", "ends_at", "crew_id")) as Array<{
      challenge_id: string;
      cadence: string;
      title: string;
      starts_at: string;
      ends_at: string;
      crew_id: string | null;
    }>;
    return reply.send({ space_id: spaceId, challenges: rows });
  });

  app.post("/v1/social/spaces/:spaceId/challenges", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const { spaceId } = spaceParamsSchema.parse(request.params ?? {});
    const body = challengeCreateSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    if (!(await hasActiveSpaceMembership(spaceId, subjectDidHash))) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", "Space membership required"));
    }
    let gate = await verifyAndGate({
      subjectDidHash,
      actionId: "challenge.create",
      actionType: "challenge_create",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: spaceId }
    }).catch(() => null);
    if (gate?.denied) {
      gate = await verifyAndGate({
        subjectDidHash,
        actionId: "social.space.moderate",
        actionType: "challenge_create",
        presentation: body.presentation,
        nonce: body.nonce,
        audience: body.audience,
        context: { space_id: spaceId }
      }).catch(() => null);
    }
    if (!gate) {
      return reply
        .code(503)
        .send(makeErrorResponse("requirements_unavailable", "Requirements unavailable"));
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const challengeId = randomUUID();
    const now = Date.now();
    const startsAt = new Date(now).toISOString();
    const endsAt = new Date(now + body.durationHours * 60 * 60 * 1000).toISOString();
    await (
      await getDb()
    )("social_space_challenges").insert({
      challenge_id: challengeId,
      space_id: spaceId,
      cadence: body.cadence,
      title: body.title,
      starts_at: startsAt,
      ends_at: endsAt,
      created_by_subject_hash: subjectDidHash,
      status: "ACTIVE",
      crew_id: body.crewId ?? null,
      created_at: startsAt
    });
    incCompleted("challenge_create");
    return reply.send({ decision: "ALLOW", challengeId });
  });

  app.post("/v1/social/challenges/:challengeId/join", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const params = z.object({ challengeId: z.string().uuid() }).parse(request.params ?? {});
    const body = challengeJoinSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const challenge = (await (await getDb())("social_space_challenges")
      .where({ challenge_id: params.challengeId, status: "ACTIVE" })
      .first()) as { challenge_id: string; space_id: string; crew_id: string | null } | undefined;
    if (!challenge) {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Challenge not found"));
    }
    if (!(await hasActiveSpaceMembership(challenge.space_id, subjectDidHash))) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", "Space membership required"));
    }
    if (challenge.crew_id && !(await isCrewMember(challenge.crew_id, subjectDidHash))) {
      return reply.code(403).send(makeErrorResponse("invalid_request", "Crew membership required"));
    }
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "challenge.join",
      actionType: "challenge_join",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: challenge.space_id }
    }).catch(() => null);
    if (!gate) {
      return reply
        .code(503)
        .send(makeErrorResponse("requirements_unavailable", "Requirements unavailable"));
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    await (
      await getDb()
    )("social_space_challenge_participation")
      .insert({
        challenge_id: params.challengeId,
        subject_hash: subjectDidHash,
        joined_at: new Date().toISOString(),
        completed_at: null
      })
      .onConflict(["challenge_id", "subject_hash"])
      .ignore();
    await publishRealtimeEvent({
      channel: "challenge",
      spaceId: challenge.space_id,
      challengeId: params.challengeId,
      eventType: "challenge.join",
      payload: {
        challengeId: params.challengeId,
        actorSubjectHash: subjectDidHash
      }
    }).catch(() => undefined);
    incCompleted("challenge_join");
    return reply.send({ decision: "ALLOW" });
  });

  app.post("/v1/social/challenges/:challengeId/complete", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const params = z.object({ challengeId: z.string().uuid() }).parse(request.params ?? {});
    const body = challengeCompleteSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const db = await getDb();
    const challenge = (await db("social_space_challenges")
      .where({ challenge_id: params.challengeId, status: "ACTIVE" })
      .first()) as
      | {
          challenge_id: string;
          space_id: string;
          cadence: "daily" | "weekly" | "ad_hoc";
          crew_id: string | null;
        }
      | undefined;
    if (!challenge) {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Challenge not found"));
    }
    if (!(await hasActiveSpaceMembership(challenge.space_id, subjectDidHash))) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", "Space membership required"));
    }
    if (challenge.crew_id && !(await isCrewMember(challenge.crew_id, subjectDidHash))) {
      return reply.code(403).send(makeErrorResponse("invalid_request", "Crew membership required"));
    }
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "challenge.complete",
      actionType: "challenge_complete",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: challenge.space_id }
    }).catch(() => null);
    if (!gate) {
      return reply
        .code(503)
        .send(makeErrorResponse("requirements_unavailable", "Requirements unavailable"));
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const participation = await db("social_space_challenge_participation")
      .where({ challenge_id: params.challengeId, subject_hash: subjectDidHash })
      .first();
    if (!participation) {
      return reply.code(409).send(makeErrorResponse("invalid_request", "Join challenge first"));
    }
    if (participation.completed_at) {
      return reply.send({ decision: "ALLOW", alreadyCompleted: true });
    }
    const evidence = await db("social_action_log")
      .where({ subject_did_hash: subjectDidHash, decision: "COMPLETE" })
      .whereIn("action_type", ["social.post.create", "social.reply.create"])
      .orderBy("created_at", "desc")
      .first();
    if (!evidence) {
      return reply
        .code(409)
        .send(
          makeErrorResponse("invalid_request", "Verified contribution required before complete")
        );
    }
    const nowIso = new Date().toISOString();
    await db("social_space_challenge_participation")
      .where({ challenge_id: params.challengeId, subject_hash: subjectDidHash })
      .update({
        completed_at: nowIso,
        evidence_action_log_id: evidence.id ?? null
      });
    if (challenge.cadence === "daily" || challenge.cadence === "weekly") {
      await applyStreakCompletion({
        spaceId: challenge.space_id,
        subjectHash: subjectDidHash,
        streakType: challenge.cadence === "daily" ? "daily_challenge" : "weekly_challenge",
        completedAtIso: nowIso
      });
    }
    await logAction({
      subjectDidHash,
      actionType: "challenge.complete",
      decision: "COMPLETE",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    await publishRealtimeEvent({
      channel: "challenge",
      spaceId: challenge.space_id,
      challengeId: params.challengeId,
      eventType: "challenge.complete",
      payload: {
        challengeId: params.challengeId,
        actorSubjectHash: subjectDidHash,
        completedAt: nowIso
      }
    }).catch(() => undefined);
    incCompleted("challenge_complete");
    return reply.send({ decision: "ALLOW" });
  });

  app.post("/v1/social/challenges/:challengeId/end", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const params = z.object({ challengeId: z.string().uuid() }).parse(request.params ?? {});
    const body = challengeEndSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const challenge = (await (await getDb())("social_space_challenges")
      .where({ challenge_id: params.challengeId, status: "ACTIVE" })
      .first()) as { challenge_id: string; space_id: string } | undefined;
    if (!challenge) {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Challenge not found"));
    }
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "challenge.end",
      actionType: "challenge_end",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: challenge.space_id }
    }).catch(() => null);
    if (!gate) {
      return reply
        .code(503)
        .send(makeErrorResponse("requirements_unavailable", "Requirements unavailable"));
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    await (await getDb())("social_space_challenges")
      .where({ challenge_id: params.challengeId })
      .update({ status: "ENDED", ended_at: new Date().toISOString() });
    incCompleted("challenge_end");
    return reply.send({ decision: "ALLOW" });
  });

  app.get("/v1/social/spaces/:spaceId/streaks", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const { spaceId } = spaceParamsSchema.parse(request.params ?? {});
    const query = z.object({ subjectDid: z.string().min(3).optional() }).parse(request.query ?? {});
    const viewerHash = query.subjectDid ? pseudonymizer.didToHash(query.subjectDid) : null;
    const ownRows = viewerHash
      ? ((await (await getDb())("social_space_streaks")
          .where({ space_id: spaceId, subject_hash: viewerHash })
          .select("streak_type", "current_count", "best_count", "last_completed_at")) as Array<{
          streak_type: string;
          current_count: number;
          best_count: number;
          last_completed_at: string | null;
        }>)
      : [];
    const topRows = (await (await getDb())("social_space_streaks")
      .where({ space_id: spaceId })
      .orderBy("current_count", "desc")
      .limit(config.LEADERBOARD_TOP_N)
      .select("streak_type", "current_count", "best_count")) as Array<{
      streak_type: string;
      current_count: number;
      best_count: number;
    }>;
    return reply.send({
      space_id: spaceId,
      you: ownRows,
      top_streaks: topRows.map((row) => ({
        streak_type: row.streak_type,
        current_count: Number(row.current_count ?? 0),
        best_count: Number(row.best_count ?? 0)
      }))
    });
  });

  app.post("/v1/social/spaces/:spaceId/banter/threads", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const { spaceId } = spaceParamsSchema.parse(request.params ?? {});
    const body = banterThreadCreateSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const space = await getSpaceById(spaceId);
    if (!space) return reply.code(404).send(makeErrorResponse("invalid_request", "Space not found"));
    if (!(await hasActiveSpaceMembership(spaceId, subjectDidHash))) {
      return reply.code(403).send(makeErrorResponse("invalid_request", "Space membership required"));
    }
    if (body.kind === "crew_chat") {
      if (!body.crewId) {
        return reply.code(400).send(makeErrorResponse("invalid_request", "crewId required"));
      }
      const crew = await getCrewById(body.crewId);
      if (!crew || crew.space_id !== spaceId) {
        return reply.code(404).send(makeErrorResponse("invalid_request", "Crew not found"));
      }
      if (!(await isCrewMember(body.crewId, subjectDidHash))) {
        return reply.code(403).send(makeErrorResponse("invalid_request", "Crew membership required"));
      }
    }
    if (body.kind === "challenge_chat") {
      if (!body.challengeId) {
        return reply.code(400).send(makeErrorResponse("invalid_request", "challengeId required"));
      }
      const challenge = (await (await getDb())("social_space_challenges")
        .where({ challenge_id: body.challengeId })
        .first()) as { space_id: string; status: string; crew_id: string | null } | undefined;
      if (!challenge || challenge.space_id !== spaceId || challenge.status !== "ACTIVE") {
        return reply.code(404).send(makeErrorResponse("invalid_request", "Challenge not found"));
      }
      if (challenge.crew_id && !(await isCrewMember(challenge.crew_id, subjectDidHash))) {
        return reply.code(403).send(makeErrorResponse("invalid_request", "Crew membership required"));
      }
    }
    if (body.kind === "hangout_chat") {
      if (!body.hangoutSessionId) {
        return reply
          .code(400)
          .send(makeErrorResponse("invalid_request", "hangoutSessionId required"));
      }
      const session = await getSyncSession(body.hangoutSessionId);
      if (!session || session.space_id !== spaceId || session.kind !== "huddle") {
        return reply.code(404).send(makeErrorResponse("invalid_request", "Hangout not found"));
      }
    }
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "banter.thread.create",
      actionType: "banter_thread_create",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: spaceId }
    }).catch(() => null);
    if (!gate) {
      return reply.code(503).send(makeErrorResponse("requirements_unavailable", "Requirements unavailable"));
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const db = await getDb();
    let existingQuery = db("social_space_banter_threads")
      .where({ space_id: spaceId, kind: body.kind })
      .whereNull("archived_at");
    existingQuery = body.crewId
      ? existingQuery.andWhere({ crew_id: body.crewId })
      : existingQuery.whereNull("crew_id");
    existingQuery = body.challengeId
      ? existingQuery.andWhere({ challenge_id: body.challengeId })
      : existingQuery.whereNull("challenge_id");
    existingQuery = body.hangoutSessionId
      ? existingQuery.andWhere({ hangout_session_id: body.hangoutSessionId })
      : existingQuery.whereNull("hangout_session_id");
    const existing = (await existingQuery.first()) as { thread_id: string } | undefined;
    if (existing?.thread_id) {
      return reply.send({ decision: "ALLOW", threadId: existing.thread_id, reused: true });
    }
    const threadId = randomUUID();
    const now = new Date().toISOString();
    await db("social_space_banter_threads").insert({
      thread_id: threadId,
      space_id: spaceId,
      kind: body.kind,
      crew_id: body.crewId ?? null,
      challenge_id: body.challengeId ?? null,
      hangout_session_id: body.hangoutSessionId ?? null,
      created_at: now,
      updated_at: now
    });
    incCompleted("banter_thread_create");
    return reply.send({ decision: "ALLOW", threadId, reused: false });
  });

  app.get("/v1/social/spaces/:spaceId/banter/threads", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    await pruneExpiredBanterRows().catch(() => undefined);
    const { spaceId } = spaceParamsSchema.parse(request.params ?? {});
    const query = banterThreadListQuerySchema.parse(request.query ?? {});
    const space = await getSpaceById(spaceId);
    if (!space) return reply.code(404).send(makeErrorResponse("invalid_request", "Space not found"));
    const db = await getDb();
    let rowsQuery = db("social_space_banter_threads")
      .where({ space_id: spaceId })
      .whereNull("archived_at")
      .orderBy("updated_at", "desc")
      .select(
        "thread_id",
        "kind",
        "crew_id",
        "challenge_id",
        "hangout_session_id",
        "created_at",
        "updated_at"
      );
    if (query.kind) rowsQuery = rowsQuery.andWhere({ kind: query.kind });
    const rows = (await rowsQuery) as Array<{
      thread_id: string;
      kind: BanterThreadKind;
      crew_id: string | null;
      challenge_id: string | null;
      hangout_session_id: string | null;
      created_at: string;
      updated_at: string;
    }>;
    const threadIds = rows.map((row) => row.thread_id);
    const countRows: Array<{ thread_id: string; count: string }> =
      threadIds.length === 0
        ? []
        : ((await db("social_banter_messages")
            .whereIn("thread_id", threadIds)
            .whereNull("deleted_at")
            .andWhere({ visibility: "normal" })
            .groupBy("thread_id")
            .select("thread_id")
            .count<{ thread_id: string; count: string }>("message_id as count")) as unknown as Array<{
            thread_id: string;
            count: string;
          }>);
    const countByThread = new Map(countRows.map((row) => [row.thread_id, Number(row.count ?? 0)]));
    return reply.send({
      spaceId,
      threads: rows.map((row) => ({
        thread_id: row.thread_id,
        kind: row.kind,
        crew_id: row.crew_id,
        challenge_id: row.challenge_id,
        hangout_session_id: row.hangout_session_id,
        message_count: countByThread.get(row.thread_id) ?? 0,
        created_at: row.created_at,
        updated_at: row.updated_at
      }))
    });
  });

  app.get("/v1/social/banter/threads/:threadId", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const { threadId } = banterThreadParamsSchema.parse(request.params ?? {});
    const thread = await getBanterThread(threadId);
    if (!thread) return reply.code(404).send(makeErrorResponse("invalid_request", "Thread not found"));
    return reply.send({
      thread_id: thread.thread_id,
      space_id: thread.space_id,
      kind: thread.kind,
      crew_id: thread.crew_id,
      challenge_id: thread.challenge_id,
      hangout_session_id: thread.hangout_session_id,
      created_at: thread.created_at,
      updated_at: thread.updated_at
    });
  });

  app.post("/v1/social/banter/threads/:threadId/permission", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const { threadId } = banterThreadParamsSchema.parse(request.params ?? {});
    const body = banterPermissionSchema.parse(request.body ?? {});
    const subjectHash = pseudonymizer.didToHash(body.subjectDid);
    const thread = await getBanterThread(threadId);
    if (!thread) return reply.code(404).send(makeErrorResponse("invalid_request", "Thread not found"));
    if (!(await hasActiveSpaceMembership(thread.space_id, subjectHash))) {
      return reply.code(403).send(makeErrorResponse("invalid_request", "Space membership required"));
    }
    const gate = await verifyAndGate({
      subjectDidHash: subjectHash,
      actionId: "banter.thread.read",
      actionType: "banter_thread_create",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: thread.space_id }
    }).catch(() => null);
    if (!gate) {
      return reply.code(503).send(makeErrorResponse("requirements_unavailable", "Requirements unavailable"));
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const permission = await mintBanterPermissionToken({ threadId, subjectHash });
    return reply.send({
      decision: "ALLOW",
      threadId,
      permissionToken: permission.token,
      expiresAt: permission.expiresAt
    });
  });

  app.get("/v1/social/banter/threads/:threadId/messages", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    await pruneExpiredBanterRows().catch(() => undefined);
    const { threadId } = banterThreadParamsSchema.parse(request.params ?? {});
    const query = banterMessagesQuerySchema.parse(request.query ?? {});
    const thread = await getBanterThread(threadId);
    if (!thread) return reply.code(404).send(makeErrorResponse("invalid_request", "Thread not found"));
    const db = await getDb();
    let messagesQuery = db("social_banter_messages")
      .where({ thread_id: threadId, visibility: "normal" })
      .whereNull("deleted_at")
      .orderBy("created_at", "desc")
      .limit(query.limit)
      .select("message_id", "thread_id", "body_text", "created_at", "visibility");
    if (query.before) {
      messagesQuery = messagesQuery.andWhere("created_at", "<", query.before);
    }
    const messages = (await messagesQuery) as Array<{
      message_id: string;
      thread_id: string;
      body_text: string | null;
      created_at: string;
      visibility: string;
    }>;
    const messageIds = messages.map((entry) => entry.message_id);
    const reactionRows: Array<{ message_id: string; count: string }> =
      messageIds.length === 0
        ? []
        : ((await db("social_banter_reactions")
            .whereIn("message_id", messageIds)
            .groupBy("message_id")
            .select("message_id")
            .count<{ message_id: string; count: string }>(
              "reactor_subject_hash as count"
            )) as unknown as Array<{
            message_id: string;
            count: string;
          }>);
    const reactionCountByMessage = new Map(
      reactionRows.map((entry) => [entry.message_id, Number(entry.count ?? 0)])
    );
    return reply.send({
      thread_id: threadId,
      messages: messages.reverse().map((entry) => ({
        message_id: entry.message_id,
        body_text: entry.body_text,
        created_at: entry.created_at,
        visibility: entry.visibility,
        reaction_count: reactionCountByMessage.get(entry.message_id) ?? 0
      }))
    });
  });

  app.post("/v1/social/banter/threads/:threadId/send", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    await pruneExpiredBanterRows().catch(() => undefined);
    const { threadId } = banterThreadParamsSchema.parse(request.params ?? {});
    const body = banterSendSchema.parse(request.body ?? {});
    const subjectHash = pseudonymizer.didToHash(body.subjectDid);
    const thread = await getBanterThread(threadId);
    if (!thread) return reply.code(404).send(makeErrorResponse("invalid_request", "Thread not found"));
    if (!(await hasActiveSpaceMembership(thread.space_id, subjectHash))) {
      return reply.code(403).send(makeErrorResponse("invalid_request", "Space membership required"));
    }
    if (thread.kind === "crew_chat" && thread.crew_id && !(await isCrewMember(thread.crew_id, subjectHash))) {
      return reply.code(403).send(makeErrorResponse("invalid_request", "Crew membership required"));
    }
    const permission = await validateBanterPermission({
      threadId,
      subjectHash,
      permissionToken: body.permissionToken
    });
    if (!permission.ok) {
      return reply.code(403).send(makeErrorResponse("invalid_request", permission.reason));
    }
    const gate = await verifyAndGate({
      subjectDidHash: subjectHash,
      actionId: "banter.message.send",
      actionType: "banter_message_send",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: thread.space_id }
    }).catch(() => null);
    if (!gate) {
      return reply.code(503).send(makeErrorResponse("requirements_unavailable", "Requirements unavailable"));
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const tier = await resolveSubjectTier(subjectHash, thread.space_id);
    const rate = checkBanterRateLimit({
      subjectHash,
      threadId,
      socialTier: tier as "bronze" | "silver" | "gold",
      moderator: false
    });
    if (!rate.ok) {
      return reply.code(429).send(makeErrorResponse("rate_limited", "Banter cooldown active"));
    }
    const messageId = randomUUID();
    const now = new Date().toISOString();
    const bodyText = body.bodyText.trim();
    await (await getDb())("social_banter_messages").insert({
      message_id: messageId,
      thread_id: threadId,
      author_subject_hash: subjectHash,
      body_text: bodyText,
      body_hash: hashHex(bodyText),
      created_at: now,
      visibility: "normal"
    });
    await (await getDb())("social_space_banter_threads")
      .where({ thread_id: threadId })
      .update({ updated_at: now });
    await publishRealtimeEvent({
      channel: "banter",
      spaceId: thread.space_id,
      threadId,
      challengeId: thread.challenge_id,
      sessionId: thread.hangout_session_id,
      eventType: "banter.message.new",
      payload: {
        threadId,
        messageId,
        createdAt: now,
        actorSubjectHash: subjectHash
      }
    }).catch(() => undefined);
    incCompleted("banter_message_send");
    return reply.send({ decision: "ALLOW", messageId, createdAt: now });
  });

  app.post("/v1/social/banter/messages/:messageId/react", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const { messageId } = banterMessageParamsSchema.parse(request.params ?? {});
    const body = banterReactSchema.parse(request.body ?? {});
    const subjectHash = pseudonymizer.didToHash(body.subjectDid);
    const message = (await (await getDb())("social_banter_messages as messages")
      .join("social_space_banter_threads as threads", "messages.thread_id", "threads.thread_id")
      .where("messages.message_id", messageId)
      .select(
        "messages.message_id",
        "messages.thread_id",
        "threads.space_id",
        "messages.deleted_at",
        "messages.visibility"
      )
      .first()) as
      | {
          message_id: string;
          thread_id: string;
          space_id: string;
          deleted_at: string | null;
          visibility: string;
        }
      | undefined;
    if (!message) return reply.code(404).send(makeErrorResponse("invalid_request", "Message not found"));
    if (message.deleted_at || message.visibility !== "normal") {
      return reply.code(409).send(makeErrorResponse("invalid_request", "Message unavailable"));
    }
    if (!(await hasActiveSpaceMembership(message.space_id, subjectHash))) {
      return reply.code(403).send(makeErrorResponse("invalid_request", "Space membership required"));
    }
    const permission = await validateBanterPermission({
      threadId: message.thread_id,
      subjectHash,
      permissionToken: body.permissionToken
    });
    if (!permission.ok) {
      return reply.code(403).send(makeErrorResponse("invalid_request", permission.reason));
    }
    const gate = await verifyAndGate({
      subjectDidHash: subjectHash,
      actionId: "banter.message.react",
      actionType: "banter_message_react",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: message.space_id }
    }).catch(() => null);
    if (!gate) {
      return reply.code(503).send(makeErrorResponse("requirements_unavailable", "Requirements unavailable"));
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const now = new Date().toISOString();
    await (
      await getDb()
    )("social_banter_reactions")
      .insert({
        message_id: messageId,
        reactor_subject_hash: subjectHash,
        emoji_id: body.emojiId ?? null,
        emoji_shortcode: body.emojiShortcode ?? null,
        created_at: now
      })
      .onConflict(["message_id", "reactor_subject_hash"])
      .merge({
        emoji_id: body.emojiId ?? null,
        emoji_shortcode: body.emojiShortcode ?? null,
        created_at: now
      });
    incCompleted("banter_message_react");
    return reply.send({ decision: "ALLOW" });
  });

  app.post("/v1/social/banter/messages/:messageId/delete", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const { messageId } = banterMessageParamsSchema.parse(request.params ?? {});
    const body = banterDeleteOwnSchema.parse(request.body ?? {});
    const subjectHash = pseudonymizer.didToHash(body.subjectDid);
    const message = (await (await getDb())("social_banter_messages as messages")
      .join("social_space_banter_threads as threads", "messages.thread_id", "threads.thread_id")
      .where("messages.message_id", messageId)
      .select("messages.author_subject_hash", "threads.space_id")
      .first()) as
      | {
          author_subject_hash: string;
          space_id: string;
        }
      | undefined;
    if (!message) return reply.code(404).send(makeErrorResponse("invalid_request", "Message not found"));
    if (message.author_subject_hash !== subjectHash) {
      return reply.code(403).send(makeErrorResponse("invalid_request", "Own message required"));
    }
    const gate = await verifyAndGate({
      subjectDidHash: subjectHash,
      actionId: "banter.message.delete_own",
      actionType: "banter_message_delete_own",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: message.space_id }
    }).catch(() => null);
    if (!gate) {
      return reply.code(503).send(makeErrorResponse("requirements_unavailable", "Requirements unavailable"));
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    await (await getDb())("social_banter_messages").where({ message_id: messageId }).update({
      body_text: null,
      deleted_at: new Date().toISOString()
    });
    incCompleted("banter_message_delete_own");
    return reply.send({ decision: "ALLOW" });
  });

  app.post("/v1/social/banter/messages/:messageId/moderate", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const { messageId } = banterMessageParamsSchema.parse(request.params ?? {});
    const body = banterModerateSchema.parse(request.body ?? {});
    const subjectHash = pseudonymizer.didToHash(body.subjectDid);
    const message = (await (await getDb())("social_banter_messages as messages")
      .join("social_space_banter_threads as threads", "messages.thread_id", "threads.thread_id")
      .where("messages.message_id", messageId)
      .select("threads.space_id")
      .first()) as { space_id: string } | undefined;
    if (!message) return reply.code(404).send(makeErrorResponse("invalid_request", "Message not found"));
    const gate = await verifyAndGate({
      subjectDidHash: subjectHash,
      actionId: "banter.message.moderate",
      actionType: "banter_message_moderate",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: message.space_id }
    }).catch(() => null);
    if (!gate) {
      return reply.code(503).send(makeErrorResponse("requirements_unavailable", "Requirements unavailable"));
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    await (await getDb())("social_banter_messages").where({ message_id: messageId }).update({
      body_text: null,
      visibility: "removed_by_mod",
      deleted_at: new Date().toISOString()
    });
    incCompleted("banter_message_moderate");
    return reply.send({ decision: "ALLOW", reasonCode: body.reasonCode });
  });

  app.post("/v1/social/spaces/:spaceId/status", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    await pruneExpiredBanterRows().catch(() => undefined);
    const { spaceId } = spaceParamsSchema.parse(request.params ?? {});
    const body = spaceStatusSetSchema.parse(request.body ?? {});
    const subjectHash = pseudonymizer.didToHash(body.subjectDid);
    if (!(await hasActiveSpaceMembership(spaceId, subjectHash))) {
      return reply.code(403).send(makeErrorResponse("invalid_request", "Space membership required"));
    }
    if (body.crewId) {
      const crew = await getCrewById(body.crewId);
      if (!crew || crew.space_id !== spaceId) {
        return reply.code(404).send(makeErrorResponse("invalid_request", "Crew not found"));
      }
      if (!(await isCrewMember(body.crewId, subjectHash))) {
        return reply.code(403).send(makeErrorResponse("invalid_request", "Crew membership required"));
      }
    }
    const gate = await verifyAndGate({
      subjectDidHash: subjectHash,
      actionId: "banter.status.set",
      actionType: "banter_status_set",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: spaceId }
    }).catch(() => null);
    if (!gate) {
      return reply.code(503).send(makeErrorResponse("requirements_unavailable", "Requirements unavailable"));
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const now = new Date().toISOString();
    await (await getDb())("social_presence_status_messages")
      .where({
        space_id: spaceId,
        subject_hash: subjectHash,
        crew_id: body.crewId ?? null
      })
      .del();
    await (await getDb())("social_presence_status_messages").insert({
      status_id: randomUUID(),
      space_id: spaceId,
      crew_id: body.crewId ?? null,
      subject_hash: subjectHash,
      status_text: body.statusText.trim(),
      status_hash: hashHex(body.statusText.trim()),
      mode: body.mode,
      updated_at: now
    });
    incCompleted("banter_status_set");
    return reply.send({ decision: "ALLOW", spaceId, updatedAt: now });
  });

  app.get("/v1/social/spaces/:spaceId/status", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    await pruneExpiredBanterRows().catch(() => undefined);
    const { spaceId } = spaceParamsSchema.parse(request.params ?? {});
    const query = spaceStatusQuerySchema.parse(request.query ?? {});
    const cutoff = new Date(Date.now() - config.BANTER_STATUS_TTL_SECONDS * 1000).toISOString();
    const rows = (await (await getDb())("social_presence_status_messages")
      .where({ space_id: spaceId })
      .andWhere("updated_at", ">=", cutoff)
      .select("subject_hash", "mode", "status_text", "updated_at")) as Array<{
      subject_hash: string;
      mode: string;
      status_text: string;
      updated_at: string;
    }>;
    const counts = { quiet: 0, active: 0, immersive: 0 };
    for (const row of rows) {
      if (row.mode === "quiet") counts.quiet += 1;
      else if (row.mode === "immersive") counts.immersive += 1;
      else counts.active += 1;
    }
    const viewerHash = query.viewerDid ? pseudonymizer.didToHash(query.viewerDid) : null;
    const own = viewerHash
      ? rows.find((row) => row.subject_hash === viewerHash)
      : undefined;
    return reply.send({
      spaceId,
      counts,
      you: own
        ? {
            mode: own.mode,
            status_text: own.status_text,
            updated_at: own.updated_at
          }
        : null
    });
  });

  app.get("/v1/social/spaces/:spaceId/pulse", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const { spaceId } = spaceParamsSchema.parse(request.params ?? {});
    const query = pulseQuerySchema.parse(request.query ?? {});
    const space = await getSpaceById(spaceId);
    if (!space) {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Space not found"));
    }
    const subjectHash = query.subjectDid ? pseudonymizer.didToHash(query.subjectDid) : null;
    if (subjectHash) {
      const privacy = await getPrivacyStatus(subjectHash).catch(() => ({
        restricted: false,
        tombstoned: false
      }));
      if (privacy.tombstoned) {
        return reply.send({ spaceId, cards: [] });
      }
    }
    const preferences = await getPulsePreferences(spaceId, subjectHash);
    const cards = await buildPulseCards({
      spaceId,
      subjectHash,
      preferences
    });
    return reply.send({ spaceId, cards });
  });

  app.get("/v1/social/spaces/:spaceId/pulse/preferences", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const { spaceId } = spaceParamsSchema.parse(request.params ?? {});
    const query = pulseQuerySchema.parse(request.query ?? {});
    const space = await getSpaceById(spaceId);
    if (!space) {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Space not found"));
    }
    const subjectHash = query.subjectDid ? pseudonymizer.didToHash(query.subjectDid) : null;
    if (subjectHash) {
      const privacy = await getPrivacyStatus(subjectHash).catch(() => ({
        restricted: false,
        tombstoned: false
      }));
      if (privacy.tombstoned) {
        return reply.send({
          spaceId,
          preferences: toPulsePreferencesResponse({ ...defaultPulsePreferences, enabled: false })
        });
      }
    }
    const preferences = await getPulsePreferences(spaceId, subjectHash);
    return reply.send({
      spaceId,
      preferences: toPulsePreferencesResponse(preferences)
    });
  });

  app.post("/v1/social/spaces/:spaceId/pulse/preferences", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const { spaceId } = spaceParamsSchema.parse(request.params ?? {});
    const body = pulsePreferencesUpdateSchema.parse(request.body ?? {});
    const subjectHash = pseudonymizer.didToHash(body.subjectDid);
    if (!(await hasActiveSpaceMembership(spaceId, subjectHash))) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", "Space membership required"));
    }
    const gate = await verifyAndGate({
      subjectDidHash: subjectHash,
      actionId: "presence.ping",
      actionType: "presence_ping",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: spaceId }
    }).catch(() => null);
    if (!gate) {
      return reply.code(503).send(
        makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
          devMode: config.DEV_MODE
        })
      );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const existing = await getPulsePreferences(spaceId, subjectHash);
    const next: PulsePreferences = {
      enabled: body.enabled ?? existing.enabled,
      notify_hangouts: body.notifyHangouts ?? existing.notify_hangouts,
      notify_crews: body.notifyCrews ?? existing.notify_crews,
      notify_challenges: body.notifyChallenges ?? existing.notify_challenges,
      notify_rankings: body.notifyRankings ?? existing.notify_rankings,
      notify_streaks: body.notifyStreaks ?? existing.notify_streaks
    };
    await upsertPulsePreferences(spaceId, subjectHash, next);
    return reply.send({
      decision: "ALLOW",
      spaceId,
      preferences: toPulsePreferencesResponse(next)
    });
  });

  app.get("/v1/social/spaces/:spaceId/rituals/active", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const { spaceId } = spaceParamsSchema.parse(request.params ?? {});
    const now = new Date().toISOString();
    const active = (await (await getDb())("social_space_rituals")
      .where({ space_id: spaceId, status: "ACTIVE" })
      .andWhere("ends_at", ">", now)
      .orderBy("starts_at", "desc")
      .select(
        "ritual_id",
        "ritual_type",
        "title",
        "description",
        "duration_minutes",
        "starts_at",
        "ends_at"
      )) as Array<Record<string, unknown>>;
    const ritualIds = active.map((row) => String(row.ritual_id));
    const participantRows =
      ritualIds.length > 0
        ? ((await (await getDb())("social_space_ritual_participants")
            .whereIn("ritual_id", ritualIds)
            .select("ritual_id", "completed_at")) as Array<{
            ritual_id: string;
            completed_at: string | null;
          }>)
        : [];
    const byRitual = new Map<string, { participation_count: number; completion_count: number }>();
    for (const row of participantRows) {
      const bucket = byRitual.get(row.ritual_id) ?? { participation_count: 0, completion_count: 0 };
      bucket.participation_count += 1;
      if (row.completed_at) bucket.completion_count += 1;
      byRitual.set(row.ritual_id, bucket);
    }
    return reply.send({
      space_id: spaceId,
      rituals: active.map((row) => ({
        ...row,
        ...(byRitual.get(String(row.ritual_id)) ?? {
          participation_count: 0,
          completion_count: 0
        })
      }))
    });
  });

  app.post("/v1/social/ritual/create", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = ritualCreateSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    if (!(await hasActiveSpaceMembership(body.spaceId, subjectDidHash))) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", "Space membership required"));
    }
    let gate = await verifyAndGate({
      subjectDidHash,
      actionId: "ritual.create",
      actionType: "ritual_create",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (!gate?.denied) {
      // allowed via ritual.create policy
    } else {
      gate = await verifyAndGate({
        subjectDidHash,
        actionId: "social.space.moderate",
        actionType: "ritual_create",
        presentation: body.presentation,
        nonce: body.nonce,
        audience: body.audience,
        context: { space_id: body.spaceId }
      }).catch(() => null);
    }
    if (!gate) {
      return reply.code(503).send(
        makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
          devMode: config.DEV_MODE
        })
      );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const ritualId = randomUUID();
    const now = Date.now();
    await (
      await getDb()
    )("social_space_rituals").insert({
      ritual_id: ritualId,
      space_id: body.spaceId,
      ritual_type: "drop_in_challenge",
      title: body.title,
      description: body.description ?? null,
      status: "ACTIVE",
      duration_minutes: body.durationMinutes,
      created_by_subject_hash: subjectDidHash,
      starts_at: new Date(now).toISOString(),
      ends_at: new Date(now + body.durationMinutes * 60_000).toISOString(),
      created_at: new Date(now).toISOString()
    });
    incCompleted("ritual_create");
    return reply.send({ decision: "ALLOW", ritualId });
  });

  app.post("/v1/social/ritual/participate", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = ritualParticipateSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    if (!(await hasActiveSpaceMembership(body.spaceId, subjectDidHash))) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", "Space membership required"));
    }
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "ritual.participate",
      actionType: "ritual_participate",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (!gate) {
      return reply.code(503).send(
        makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
          devMode: config.DEV_MODE
        })
      );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const ritual = await (await getDb())("social_space_rituals")
      .where({ ritual_id: body.ritualId, space_id: body.spaceId, status: "ACTIVE" })
      .first();
    if (!ritual) {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Ritual not found"));
    }
    await (
      await getDb()
    )("social_space_ritual_participants")
      .insert({
        ritual_id: body.ritualId,
        space_id: body.spaceId,
        subject_hash: subjectDidHash,
        participated_at: new Date().toISOString(),
        completed_at: null,
        completion_count: 0
      })
      .onConflict(["ritual_id", "subject_hash"])
      .ignore();
    incCompleted("ritual_participate");
    return reply.send({ decision: "ALLOW" });
  });

  app.post("/v1/social/ritual/complete", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = ritualCompleteSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    if (!(await hasActiveSpaceMembership(body.spaceId, subjectDidHash))) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", "Space membership required"));
    }
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "ritual.complete",
      actionType: "ritual_complete",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (!gate) {
      return reply.code(503).send(
        makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
          devMode: config.DEV_MODE
        })
      );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const db = await getDb();
    const ritual = await db("social_space_rituals")
      .where({ ritual_id: body.ritualId, space_id: body.spaceId, status: "ACTIVE" })
      .first();
    if (!ritual) {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Ritual not found"));
    }
    const joined = await db("social_space_ritual_participants")
      .where({ ritual_id: body.ritualId, subject_hash: subjectDidHash })
      .first();
    if (!joined) {
      return reply
        .code(409)
        .send(makeErrorResponse("invalid_request", "Participate before complete"));
    }
    const todayStart = new Date();
    todayStart.setUTCHours(0, 0, 0, 0);
    const todayCount = await db("social_space_ritual_participants")
      .where({ subject_hash: subjectDidHash, space_id: body.spaceId })
      .whereNotNull("completed_at")
      .andWhere("completed_at", ">=", todayStart.toISOString())
      .count<{ count: string }>("ritual_id as count")
      .first();
    if (Number(todayCount?.count ?? 0) >= 3) {
      return reply
        .code(429)
        .send(makeErrorResponse("invalid_request", "Daily ritual completion cap reached"));
    }
    if (joined.completed_at) {
      return reply.send({ decision: "ALLOW", alreadyCompleted: true });
    }
    await db("social_space_ritual_participants")
      .where({ ritual_id: body.ritualId, subject_hash: subjectDidHash })
      .update({
        completed_at: new Date().toISOString(),
        completion_count: db.raw("LEAST(completion_count + 1, 1)")
      });
    await logAction({
      subjectDidHash,
      actionType: "ritual.complete",
      decision: "COMPLETE",
      policyId: gate.allowMeta?.policyId,
      policyVersion: gate.allowMeta?.policyVersion
    }).catch(() => undefined);
    incCompleted("ritual_complete");
    return reply.send({ decision: "ALLOW" });
  });

  app.post("/v1/social/ritual/end", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = ritualEndSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    let gate = await verifyAndGate({
      subjectDidHash,
      actionId: "ritual.end_session",
      actionType: "ritual_end",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (gate?.denied) {
      gate = await verifyAndGate({
        subjectDidHash,
        actionId: "social.space.moderate",
        actionType: "ritual_end",
        presentation: body.presentation,
        nonce: body.nonce,
        audience: body.audience,
        context: { space_id: body.spaceId }
      }).catch(() => null);
    }
    if (!gate) {
      return reply.code(503).send(
        makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
          devMode: config.DEV_MODE
        })
      );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const updated = await (await getDb())("social_space_rituals")
      .where({ ritual_id: body.ritualId, space_id: body.spaceId, status: "ACTIVE" })
      .update({ status: "ENDED", closed_at: new Date().toISOString() });
    if (!updated) {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Ritual not found"));
    }
    incCompleted("ritual_end");
    return reply.send({ decision: "ALLOW" });
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
    const visiblePostRows: Array<{
      post_id: string;
      content_text: string;
      content_hash: string;
      image_refs: string[];
      created_at: string;
      replies: Array<Record<string, unknown>>;
    }> = [];
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
      visiblePostRows.push({
        post_id: post.post_id,
        content_text: post.content_text,
        content_hash: post.content_hash,
        image_refs: Array.isArray(post.image_refs) ? post.image_refs : [],
        created_at: post.created_at,
        replies: []
      });
    }
    const visiblePosts = await redactPostImageRefs(visiblePostRows);
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
    const flowRows = diversified.map((entry) => ({
      post_id: entry.row.post_id,
      content_text: entry.row.content_text,
      content_hash: entry.row.content_hash,
      image_refs: Array.isArray(entry.row.image_refs) ? entry.row.image_refs : [],
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
    const posts = await redactPostImageRefs(flowRows);
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

  app.post("/v1/social/media/upload/request", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    await maybeCleanupStaleUploads().catch(() => undefined);
    const body = mediaUploadRequestSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    let gate: Awaited<ReturnType<typeof verifyAndGate>> | null = null;
    if (body.spaceId) {
      const space = await getSpaceById(body.spaceId);
      if (!space) return reply.code(404).send(makeErrorResponse("invalid_request", "Space not found"));
      const policyPack = await getSpacePolicyPack(space.policy_pack_id);
      if (!policyPack) {
        return reply
          .code(409)
          .send(makeErrorResponse("invalid_request", "Space policy pack unavailable"));
      }
      gate = await verifyAndGate({
        subjectDidHash,
        actionId: policyPack.post_action_id,
        actionType: "space_post",
        presentation: body.presentation,
        nonce: body.nonce,
        audience: body.audience,
        pinnedPolicyHash: policyPack.pinned_policy_hash_post ?? policyPack.post_policy_hash ?? null,
        context: { space_id: body.spaceId }
      }).catch(() => null);
    } else {
      gate = await verifyAndGate({
        subjectDidHash,
        actionId: "social.post.create",
        actionType: "post",
        presentation: body.presentation,
        nonce: body.nonce,
        audience: body.audience
      }).catch(() => null);
    }
    if (!gate) {
      return reply.code(503).send(
        makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
          devMode: config.DEV_MODE
        })
      );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const assetId = randomUUID();
    const objectKey = buildMediaObjectKey({
      ownerSubjectHash: subjectDidHash,
      mimeType: body.mimeType,
      kind: "original"
    });
    const presigned = await createPresignedUpload({
      objectKey,
      mimeType: body.mimeType,
      ownerSubjectHash: subjectDidHash,
      sha256Hex: body.sha256Hex,
      byteSize: body.byteSize
    });
    await (
      await getDb()
    )("social_media_assets").insert({
      asset_id: assetId,
      owner_subject_hash: subjectDidHash,
      space_id: body.spaceId ?? null,
      media_kind: "image",
      storage_provider: config.MEDIA_STORAGE_PROVIDER,
      object_key: objectKey,
      mime_type: body.mimeType,
      byte_size: body.byteSize,
      sha256_hex: body.sha256Hex,
      status: "PENDING",
      created_at: new Date().toISOString()
    });
    return reply.send({
      decision: "ALLOW",
      assetId,
      objectKey,
      uploadUrl: presigned.uploadUrl,
      requiredHeaders: presigned.requiredHeaders
    });
  });

  app.post("/v1/social/media/upload/complete", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    await maybeCleanupStaleUploads().catch(() => undefined);
    const body = mediaUploadCompleteSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const row = await (await getDb())("social_media_assets")
      .where({
        asset_id: body.assetId,
        owner_subject_hash: subjectDidHash,
        object_key: body.objectKey,
        media_kind: "image"
      })
      .first();
    if (!row) return reply.code(404).send(makeErrorResponse("invalid_request", "Upload not found"));
    const verified = await verifyUploadedObject({
      objectKey: body.objectKey,
      expectedMimeType: String(row.mime_type),
      expectedSha256Hex: String(row.sha256_hex),
      expectedByteSize: Number(row.byte_size)
    }).catch(() => null);
    if (!verified?.ok) {
      return reply.code(409).send(
        makeErrorResponse("invalid_request", "Uploaded object failed verification", {
          devMode: config.DEV_MODE,
          debug: config.DEV_MODE
            ? {
                cause: `media_verify_failed:${JSON.stringify({
                  expected: {
                    mimeType: String(row.mime_type),
                    sha256Hex: String(row.sha256_hex),
                    byteSize: Number(row.byte_size)
                  },
                  observed: verified
                })}`
              }
            : undefined
        })
      );
    }
    const thumbKey = await generateThumbnail({
      sourceObjectKey: String(row.object_key),
      ownerSubjectHash: subjectDidHash,
      mimeType: String(row.mime_type)
    }).catch(() => null);
    await (await getDb())("social_media_assets")
      .where({ asset_id: body.assetId })
      .update({
        status: "ACTIVE",
        thumbnail_object_key: thumbKey,
        finalized_at: new Date().toISOString()
      });
    return reply.send({
      decision: "ALLOW",
      assetId: body.assetId,
      imageRef: body.assetId,
      thumbnailObjectKey: thumbKey
    });
  });

  app.post("/v1/social/media/view/request", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const bucketKey = request.ip || "unknown";
    if (!checkMediaViewRateLimit(bucketKey)) {
      return reply.code(429).send(makeErrorResponse("rate_limited", "Media view rate limit exceeded"));
    }
    const body = mediaViewRequestSchema.parse(request.body ?? {});
    const viewerDidHash = body.viewerDid ? pseudonymizer.didToHash(body.viewerDid) : null;
    const unavailable = (assetId: string) => ({ assetId, status: "unavailable" as const });
    if (viewerDidHash) {
      const privacy = await getPrivacyStatus(viewerDidHash).catch(() => null);
      if (!privacy || privacy.tombstoned) {
        return reply.send({
          results: body.items.map((item) => unavailable(item.assetId))
        });
      }
    }

    const db = await getDb();
    const uniqueAssetIds = Array.from(new Set(body.items.map((item) => item.assetId)));
    const assetRows = (await db("social_media_assets")
      .whereIn("asset_id", uniqueAssetIds)
      .select(
        "asset_id",
        "object_key",
        "thumbnail_object_key",
        "status",
        "finalized_at",
        "erased_at",
        "deleted_at",
        "media_kind"
      )) as Array<{
      asset_id: string;
      object_key: string;
      thumbnail_object_key: string | null;
      status: string;
      finalized_at: string | null;
      erased_at: string | null;
      deleted_at: string | null;
      media_kind: string;
    }>;
    const assetsById = new Map(assetRows.map((row) => [row.asset_id, row]));

    const postIds = Array.from(
      new Set(body.items.filter((item) => item.context.kind === "post").map((item) => item.context.postId))
    );
    const postRows = postIds.length
      ? ((await db("social_posts")
          .whereIn("post_id", postIds)
          .whereNull("deleted_at")
          .select("post_id", "image_refs", "author_subject_did_hash")) as Array<{
          post_id: string;
          image_refs: unknown;
          author_subject_did_hash: string;
        }>)
      : [];
    const postsById = new Map(postRows.map((row) => [row.post_id, row]));

    const spacePostIds = Array.from(
      new Set(
        body.items
          .filter((item) => item.context.kind === "spacePost")
          .map((item) => item.context.postId)
      )
    );
    const spacePostRows = spacePostIds.length
      ? ((await db("social_space_posts")
          .whereIn("space_post_id", spacePostIds)
          .whereNull("deleted_at")
          .select("space_post_id", "space_id", "image_refs", "author_subject_did_hash")) as Array<{
          space_post_id: string;
          space_id: string;
          image_refs: unknown;
          author_subject_did_hash: string;
        }>)
      : [];
    const spacePostsById = new Map(spacePostRows.map((row) => [row.space_post_id, row]));
    const spaceIds = Array.from(
      new Set(
        body.items.flatMap((item) =>
          item.context.kind === "spacePost" ? [item.context.spaceId] : []
        )
      )
    );
    const spaces = spaceIds.length
      ? ((await db("social_spaces")
          .whereIn("space_id", spaceIds)
          .whereNull("archived_at")
          .select("space_id", "policy_pack_id")) as Array<{ space_id: string; policy_pack_id: string }>)
      : [];
    const spacesById = new Map(spaces.map((space) => [space.space_id, space]));
    const policyPackIds = Array.from(new Set(spaces.map((space) => space.policy_pack_id)));
    const policyRows = policyPackIds.length
      ? ((await db("social_space_policy_packs")
          .whereIn("policy_pack_id", policyPackIds)
          .select("policy_pack_id", "visibility")) as Array<{
          policy_pack_id: string;
          visibility: string;
        }>)
      : [];
    const visibilityByPolicyPack = new Map(
      policyRows.map((row) => [row.policy_pack_id, row.visibility ?? "members"])
    );

    const authorHashes = Array.from(
      new Set([
        ...postRows.map((row) => row.author_subject_did_hash),
        ...spacePostRows.map((row) => row.author_subject_did_hash)
      ])
    );
    const authorPrivacy = new Map<string, PrivacyStatus | null>();
    await Promise.all(
      authorHashes.map(async (authorHash) => {
        const privacy = await getPrivacyStatus(authorHash).catch(() => null);
        authorPrivacy.set(authorHash, privacy);
      })
    );

    const membershipCache = new Map<string, boolean>();
    const canReadSpace = async (spaceId: string) => {
      if (!viewerDidHash) return false;
      const key = `${spaceId}:${viewerDidHash}`;
      const cached = membershipCache.get(key);
      if (cached !== undefined) return cached;
      const allowed = await hasActiveSpaceMembership(spaceId, viewerDidHash);
      membershipCache.set(key, allowed);
      return allowed;
    };

    const expiresIn = config.MEDIA_PRESIGN_TTL_SECONDS;
    const expiresAt = new Date(Date.now() + expiresIn * 1000).toISOString();
    const results: Array<
      | {
          assetId: string;
          status: "ok";
          originalUrl: string;
          thumbUrl: string | null;
          expiresAt: string;
        }
      | {
          assetId: string;
          status: "unavailable";
        }
    > = [];

    for (const item of body.items) {
      const asset = assetsById.get(item.assetId);
      if (!asset || !isMediaAssetViewable(asset)) {
        results.push(unavailable(item.assetId));
        continue;
      }
      if (item.context.kind === "post") {
        const post = postsById.get(item.context.postId);
        const refs = Array.isArray(post?.image_refs) ? post.image_refs : [];
        const privacy = post ? authorPrivacy.get(post.author_subject_did_hash) : null;
        if (!post || !privacy || privacy.tombstoned || !refs.includes(item.assetId)) {
          results.push(unavailable(item.assetId));
          continue;
        }
      } else {
        const spacePost = spacePostsById.get(item.context.postId);
        const refs = Array.isArray(spacePost?.image_refs) ? spacePost.image_refs : [];
        const space = spacesById.get(item.context.spaceId);
        const visibility = space ? visibilityByPolicyPack.get(space.policy_pack_id) ?? "members" : "members";
        const privacy = spacePost ? authorPrivacy.get(spacePost.author_subject_did_hash) : null;
        const viewerRestricted = viewerDidHash
          ? await isSpaceMemberRestricted(item.context.spaceId, viewerDidHash)
          : false;
        const canReadMembersSpace =
          visibility !== "members" ? true : await canReadSpace(item.context.spaceId);
        if (
          !spacePost ||
          !space ||
          spacePost.space_id !== item.context.spaceId ||
          !privacy ||
          privacy?.restricted ||
          privacy?.tombstoned ||
          viewerRestricted ||
          !canReadMembersSpace ||
          !refs.includes(item.assetId)
        ) {
          results.push(unavailable(item.assetId));
          continue;
        }
      }
      const original = await mediaStorageAdapter
        .createPresignedGet({
          objectKey: asset.object_key,
          expiresInSeconds: expiresIn
        })
        .catch(() => null);
      if (!original?.url) {
        results.push(unavailable(item.assetId));
        continue;
      }
      const thumb = asset.thumbnail_object_key
        ? await mediaStorageAdapter
            .createPresignedGet({
              objectKey: asset.thumbnail_object_key,
              expiresInSeconds: expiresIn
            })
            .catch(() => null)
        : null;
      results.push({
        assetId: item.assetId,
        status: "ok",
        originalUrl: original.url,
        thumbUrl: thumb?.url ?? null,
        expiresAt
      });
    }

    return reply.send({ results });
  });

  app.post("/v1/social/realtime/token", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = realtimeTokenSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    if (!(await hasActiveSpaceMembership(body.spaceId, subjectDidHash))) {
      return reply.code(403).send(makeErrorResponse("invalid_request", "Space membership required"));
    }
    const actionId =
      body.channel === "presence"
        ? "presence.ping"
        : body.channel === "banter"
          ? "banter.message.send"
          : body.channel === "hangout"
            ? "sync.huddle.join_session"
            : "challenge.join";
    const actionType: FunnelAction =
      body.channel === "presence"
        ? "presence_ping"
        : body.channel === "banter"
          ? "banter_message_send"
          : body.channel === "hangout"
            ? "hangout_join"
            : "challenge_join";
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId,
      actionType,
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (!gate) {
      return reply.code(503).send(
        makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
          devMode: config.DEV_MODE
        })
      );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const token = await mintRealtimePermissionToken({
      subjectHash: subjectDidHash,
      channel: body.channel,
      spaceId: body.spaceId,
      threadId: body.threadId,
      sessionId: body.sessionId,
      challengeId: body.challengeId,
      canBroadcast: body.canBroadcast
    });
    return reply.send({
      decision: "ALLOW",
      permissionToken: token.token,
      expiresAt: token.expiresAt
    });
  });

  app.post("/v1/social/realtime/publish", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = realtimePublishSchema.parse(request.body ?? {});
    const permissionHash = hashHex(body.permissionToken);
    if (!checkRealtimeBroadcastRate(permissionHash)) {
      return reply
        .code(429)
        .send(makeErrorResponse("rate_limited", "Realtime publish rate limit exceeded"));
    }
    const permission = await validateRealtimePermission({ permissionToken: body.permissionToken });
    if (!permission.ok) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", `Realtime permission denied: ${permission.reason}`));
    }
    if (!permission.permission.canBroadcast) {
      return reply.code(403).send(makeErrorResponse("invalid_request", "Broadcast not permitted"));
    }
    const payloadString = JSON.stringify(body.payload ?? null);
    if (Buffer.byteLength(payloadString, "utf8") > config.REALTIME_EVENT_MAX_PAYLOAD_BYTES) {
      return reply.code(413).send(makeErrorResponse("invalid_request", "Realtime payload too large"));
    }
    const event = await publishRealtimeEvent({
      channel: permission.permission.channel as "presence" | "banter" | "hangout" | "challenge",
      spaceId: permission.permission.spaceId,
      threadId: permission.permission.threadId,
      sessionId: permission.permission.sessionId,
      challengeId: permission.permission.challengeId,
      eventType: body.eventType,
      payload: {
        ...((body.payload ?? {}) as Record<string, unknown>),
        actor_subject_hash: permission.permission.subjectHash
      }
    });
    return reply.send({
      decision: "ALLOW",
      eventId: event.eventId,
      createdAt: event.createdAt,
      cursor: event.cursor
    });
  });

  app.get("/v1/social/realtime/events", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const query = realtimeEventsQuerySchema.parse(request.query ?? {});
    const permission = await validateRealtimePermission({ permissionToken: query.permissionToken });
    if (!permission.ok) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", `Realtime permission denied: ${permission.reason}`));
    }
    const db = await getDb();
    const rows = (await db("social_realtime_events")
      .where({ channel: permission.permission.channel, space_id: permission.permission.spaceId })
      .modify((builder) => {
        if (permission.permission.threadId) builder.andWhere("thread_id", permission.permission.threadId);
        if (permission.permission.sessionId) builder.andWhere("session_id", permission.permission.sessionId);
        if (permission.permission.challengeId) {
          builder.andWhere("challenge_id", permission.permission.challengeId);
        }
      })
      .modify((builder) => {
        if (query.after) {
          builder.andWhere("event_cursor", ">", query.after);
          return;
        }
        if (query.since) builder.andWhere("created_at", ">", query.since);
      })
      .orderBy("event_cursor", "asc")
      .limit(query.limit)) as Array<{
      event_id: string;
      event_cursor: string | number | bigint | null;
      channel: string;
      event_type: string;
      payload_json: unknown;
      created_at: string;
    }>;
    const events = rows.map((row) => ({
      eventId: row.event_id,
      cursor: row.event_cursor === null || row.event_cursor === undefined ? null : String(row.event_cursor),
      channel: row.channel,
      eventType: row.event_type,
      payload: row.payload_json ?? {},
      createdAt: row.created_at
    }));
    return reply.send({
      events,
      nextCursor: events.length > 0 ? events[events.length - 1]?.cursor ?? null : null
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
      return reply.code(503).send(
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
      return reply.code(503).send(
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
      return reply.code(503).send(
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
      return reply.code(503).send(
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
      return reply.code(503).send(
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
      return reply.code(503).send(
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
      return reply.code(503).send(
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
      return reply.code(503).send(
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
      return reply.code(503).send(
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
      return reply.code(503).send(
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

  app.get("/v1/social/spaces/:spaceId/presence", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const { spaceId } = spaceParamsSchema.parse(request.params ?? {});
    const query = spacePresenceQuerySchema.parse(request.query ?? {});
    await pruneExpiredPresenceRows().catch(() => undefined);
    const space = await getSpaceById(spaceId);
    if (!space) {
      return reply.code(404).send(makeErrorResponse("invalid_request", "Space not found"));
    }
    const cutoff = new Date(Date.now() - config.PRESENCE_PING_TTL_SECONDS * 1000).toISOString();
    const counts = await getPresenceCounts(spaceId, cutoff);
    let yourMode: string | null = null;
    let yourCrewActiveCount = 0;
    if (query.subjectDid) {
      const subjectHash = pseudonymizer.didToHash(query.subjectDid);
      const row = await (
        await getDb()
      )("presence_space_states as states")
        .join("social_space_presence_pings as pings", function joinPresence() {
          this.on("states.space_id", "=", "pings.space_id").andOn(
            "states.subject_hash",
            "=",
            "pings.subject_hash"
          );
        })
        .where("states.space_id", spaceId)
        .andWhere("states.subject_hash", subjectHash)
        .andWhere("pings.last_seen_at", ">=", cutoff)
        .select("states.mode")
        .first();
      yourMode = row?.mode ? String(row.mode) : null;
      const crewMembership = (await (
        await getDb()
      )("social_space_crew_members as members")
        .join("social_space_crews as crews", "members.crew_id", "crews.crew_id")
        .where({
          "members.subject_hash": subjectHash,
          "crews.space_id": spaceId
        })
        .whereNull("members.left_at")
        .whereNull("crews.archived_at")
        .select("members.crew_id")
        .first()) as { crew_id?: string } | undefined;
      if (crewMembership?.crew_id) {
        const crewActive = await (
          await getDb()
        )("social_space_crew_members as members")
          .join("social_space_presence_pings as pings", function joinCrewActive() {
            this.on("members.subject_hash", "=", "pings.subject_hash");
          })
          .where({ "members.crew_id": crewMembership.crew_id })
          .whereNull("members.left_at")
          .andWhere("pings.space_id", spaceId)
          .andWhere("pings.last_seen_at", ">=", cutoff)
          .count<{ count: string }>("members.subject_hash as count")
          .first();
        yourCrewActiveCount = Number(crewActive?.count ?? 0);
      }
    }
    return reply.send({
      space_id: spaceId,
      ttl_seconds: config.PRESENCE_PING_TTL_SECONDS,
      counts,
      you: { mode: yourMode, active: Boolean(yourMode) },
      crew: {
        active_count: yourCrewActiveCount
      }
    });
  });

  app.post("/v1/social/spaces/:spaceId/presence/ping", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const { spaceId } = spaceParamsSchema.parse(request.params ?? {});
    const body = presencePingSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    if (!(await hasActiveSpaceMembership(spaceId, subjectDidHash))) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", "Space membership required"));
    }
    if (body.crewId) {
      const crew = await getCrewById(body.crewId);
      if (!crew || crew.space_id !== spaceId) {
        return reply.code(404).send(makeErrorResponse("invalid_request", "Crew not found"));
      }
      if (!(await isCrewMember(body.crewId, subjectDidHash))) {
        return reply
          .code(403)
          .send(makeErrorResponse("invalid_request", "Crew membership required"));
      }
    }
    if (!checkPresencePingRateLimit(subjectDidHash, spaceId)) {
      return reply.code(429).send(makeErrorResponse("invalid_request", "Presence ping rate limit"));
    }
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "presence.ping",
      actionType: "presence_ping",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: spaceId }
    }).catch(() => null);
    if (!gate) {
      return reply.code(503).send(
        makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
          devMode: config.DEV_MODE
        })
      );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const now = new Date().toISOString();
    const db = await getDb();
    await db("social_space_presence_pings")
      .insert({ space_id: spaceId, subject_hash: subjectDidHash, last_seen_at: now })
      .onConflict(["space_id", "subject_hash"])
      .merge({ last_seen_at: now });
    if (body.mode) {
      await db("presence_space_states")
        .insert({
          space_id: spaceId,
          subject_hash: subjectDidHash,
          mode: body.mode,
          updated_at: now
        })
        .onConflict(["space_id", "subject_hash"])
        .merge({ mode: body.mode, updated_at: now });
    }
    await pruneExpiredPresenceRows().catch(() => undefined);
    await publishRealtimeEvent({
      channel: "presence",
      spaceId,
      eventType: "presence.ping",
      payload: {
        actorSubjectHash: subjectDidHash,
        mode: body.mode ?? "active",
        crewId: body.crewId ?? null,
        observedAt: now
      }
    }).catch(() => undefined);
    incCompleted("presence_ping");
    return reply.send({
      decision: "ALLOW",
      active_until_seconds: config.PRESENCE_PING_TTL_SECONDS
    });
  });

  app.post("/v1/social/spaces/:spaceId/profile/visibility", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const { spaceId } = spaceParamsSchema.parse(request.params ?? {});
    const body = profileVisibilitySchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    if (!(await hasActiveSpaceMembership(spaceId, subjectDidHash))) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", "Space membership required"));
    }
    const gate = await verifyAndGate({
      subjectDidHash,
      actionId: "presence.ping",
      actionType: "presence_ping",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: spaceId }
    }).catch(() => null);
    if (!gate) {
      return reply.code(503).send(
        makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
          devMode: config.DEV_MODE
        })
      );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    await (
      await getDb()
    )("social_space_profile_settings")
      .insert({
        space_id: spaceId,
        subject_hash: subjectDidHash,
        show_on_leaderboard: body.showOnLeaderboard,
        show_on_presence: body.showOnPresence,
        presence_label: body.presenceLabel ?? null,
        updated_at: new Date().toISOString()
      })
      .onConflict(["space_id", "subject_hash"])
      .merge({
        show_on_leaderboard: body.showOnLeaderboard,
        show_on_presence: body.showOnPresence,
        presence_label: body.presenceLabel ?? null,
        updated_at: new Date().toISOString()
      });
    return reply.send({ decision: "ALLOW" });
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
      return reply.code(503).send(
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
      return reply.code(503).send(
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
      return reply.code(503).send(
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
      return reply.code(503).send(
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
      return reply.code(503).send(
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
      return reply.code(503).send(
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

  app.post("/v1/social/sync/huddle/create_session", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = huddleCreateSessionSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    if (!(await hasActiveSpaceMembership(body.spaceId, subjectDidHash))) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", "Space membership required"));
    }
    let gate = await verifyAndGate({
      subjectDidHash,
      actionId: "sync.huddle.create_session",
      actionType: "huddle_create",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (gate?.denied) {
      gate = await verifyAndGate({
        subjectDidHash,
        actionId: "social.space.moderate",
        actionType: "huddle_create",
        presentation: body.presentation,
        nonce: body.nonce,
        audience: body.audience,
        context: { space_id: body.spaceId }
      }).catch(() => null);
    }
    if (!gate) {
      return reply.code(503).send(
        makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
          devMode: config.DEV_MODE
        })
      );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const now = new Date().toISOString();
    const sessionId = randomUUID();
    await (
      await getDb()
    ).transaction(async (trx) => {
      await trx("sync_sessions").insert({
        session_id: sessionId,
        space_id: body.spaceId,
        kind: "huddle",
        host_subject_did_hash: subjectDidHash,
        status: "ACTIVE",
        created_at: now
      });
      await trx("sync_session_participants").insert({
        session_id: sessionId,
        subject_did_hash: subjectDidHash,
        role: "host",
        joined_at: now
      });
    });
    incCompleted("huddle_create");
    return reply.send({ decision: "ALLOW", sessionId, host_present: true, participant_count: 1 });
  });

  app.post("/v1/social/sync/huddle/join_session", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = huddleJoinSessionSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const sessionAccess = await ensureSyncSessionAccess({
      sessionId: body.sessionId,
      spaceId: body.spaceId,
      expectedKind: "huddle"
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
      actionId: "sync.huddle.join_session",
      actionType: "huddle_join",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (!gate) {
      return reply.code(503).send(
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
    const participantCountRow = await (await getDb())("sync_session_participants")
      .where({ session_id: body.sessionId })
      .whereNull("left_at")
      .count<{ count: string }>("session_id as count")
      .first();
    incCompleted("huddle_join");
    return reply.send({
      decision: "ALLOW",
      participant_count: Number(participantCountRow?.count ?? 0),
      host_present: true
    });
  });

  app.post("/v1/social/sync/huddle/end_session", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = huddleEndSessionSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const sessionAccess = await ensureSyncSessionAccess({
      sessionId: body.sessionId,
      spaceId: body.spaceId,
      expectedKind: "huddle"
    });
    if (!sessionAccess.session) {
      return reply.code(404).send(sessionAccess.error);
    }
    let gate = await verifyAndGate({
      subjectDidHash,
      actionId: "sync.huddle.end_session",
      actionType: "huddle_end",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    let endedByModerator = false;
    if (gate?.denied) {
      gate = await verifyAndGate({
        subjectDidHash,
        actionId: "social.space.moderate",
        actionType: "huddle_end",
        presentation: body.presentation,
        nonce: body.nonce,
        audience: body.audience,
        context: { space_id: body.spaceId }
      }).catch(() => null);
      endedByModerator = Boolean(gate && !gate.denied);
    }
    if (!gate) {
      return reply.code(503).send(
        makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
          devMode: config.DEV_MODE
        })
      );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    if (!endedByModerator && sessionAccess.session.host_subject_did_hash !== subjectDidHash) {
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
      await trx("sync_session_reports").insert({
        report_id: randomUUID(),
        session_id: body.sessionId,
        reporter_subject_did_hash: subjectDidHash,
        reason_code: endedByModerator ? "moderation_kill_switch" : body.reasonCode,
        created_at: now
      });
    });
    incCompleted("huddle_end");
    return reply.send({
      decision: "ALLOW",
      ended_by: endedByModerator ? "moderator" : "host",
      moderation_kill_switch: endedByModerator
    });
  });

  app.post("/v1/social/sync/hangout/create_session", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = huddleCreateSessionSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    if (!(await hasActiveSpaceMembership(body.spaceId, subjectDidHash))) {
      return reply
        .code(403)
        .send(makeErrorResponse("invalid_request", "Space membership required"));
    }
    let gate = await verifyAndGate({
      subjectDidHash,
      actionId: "sync.hangout.create_session",
      actionType: "hangout_create",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (gate?.denied) {
      gate = await verifyAndGate({
        subjectDidHash,
        actionId: "social.space.moderate",
        actionType: "hangout_create",
        presentation: body.presentation,
        nonce: body.nonce,
        audience: body.audience,
        context: { space_id: body.spaceId }
      }).catch(() => null);
    }
    if (!gate) {
      return reply.code(503).send(
        makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
          devMode: config.DEV_MODE
        })
      );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    const now = new Date().toISOString();
    const sessionId = randomUUID();
    await (
      await getDb()
    ).transaction(async (trx) => {
      await trx("sync_sessions").insert({
        session_id: sessionId,
        space_id: body.spaceId,
        kind: "huddle",
        host_subject_did_hash: subjectDidHash,
        status: "ACTIVE",
        created_at: now
      });
      await trx("sync_session_participants").insert({
        session_id: sessionId,
        subject_did_hash: subjectDidHash,
        role: "host",
        joined_at: now
      });
    });
    incCompleted("hangout_create");
    return reply.send({ decision: "ALLOW", sessionId, host_present: true, participant_count: 1 });
  });

  app.post("/v1/social/sync/hangout/join_session", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = huddleJoinSessionSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const sessionAccess = await ensureSyncSessionAccess({
      sessionId: body.sessionId,
      spaceId: body.spaceId,
      expectedKind: "huddle"
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
      actionId: "sync.hangout.join_session",
      actionType: "hangout_join",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    if (!gate) {
      return reply.code(503).send(
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
    const participantCountRow = await (await getDb())("sync_session_participants")
      .where({ session_id: body.sessionId })
      .whereNull("left_at")
      .count<{ count: string }>("session_id as count")
      .first();
    await publishRealtimeEvent({
      channel: "hangout",
      spaceId: body.spaceId,
      sessionId: body.sessionId,
      eventType: "hangout.join",
      payload: {
        sessionId: body.sessionId,
        actorSubjectHash: subjectDidHash
      }
    }).catch(() => undefined);
    incCompleted("hangout_join");
    return reply.send({
      decision: "ALLOW",
      participant_count: Number(participantCountRow?.count ?? 0),
      host_present: true
    });
  });

  app.post("/v1/social/sync/hangout/end_session", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["social:proxy"] });
    if (reply.sent) return;
    const body = huddleEndSessionSchema.parse(request.body ?? {});
    const subjectDidHash = pseudonymizer.didToHash(body.subjectDid);
    const sessionAccess = await ensureSyncSessionAccess({
      sessionId: body.sessionId,
      spaceId: body.spaceId,
      expectedKind: "huddle"
    });
    if (!sessionAccess.session) {
      return reply.code(404).send(sessionAccess.error);
    }
    let gate = await verifyAndGate({
      subjectDidHash,
      actionId: "sync.hangout.end_session",
      actionType: "hangout_end",
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      context: { space_id: body.spaceId }
    }).catch(() => null);
    let endedByModerator = false;
    if (gate?.denied) {
      gate = await verifyAndGate({
        subjectDidHash,
        actionId: "social.space.moderate",
        actionType: "hangout_end",
        presentation: body.presentation,
        nonce: body.nonce,
        audience: body.audience,
        context: { space_id: body.spaceId }
      }).catch(() => null);
      endedByModerator = Boolean(gate && !gate.denied);
    }
    if (!gate) {
      return reply.code(503).send(
        makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
          devMode: config.DEV_MODE
        })
      );
    }
    if (gate.denied) return reply.code(403).send(gate.denied);
    if (!endedByModerator && sessionAccess.session.host_subject_did_hash !== subjectDidHash) {
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
      await trx("sync_session_reports").insert({
        report_id: randomUUID(),
        session_id: body.sessionId,
        reporter_subject_did_hash: subjectDidHash,
        reason_code: endedByModerator ? "moderation_kill_switch" : body.reasonCode,
        created_at: now
      });
    });
    await publishRealtimeEvent({
      channel: "hangout",
      spaceId: body.spaceId,
      sessionId: body.sessionId,
      eventType: "hangout.end",
      payload: {
        sessionId: body.sessionId,
        endedBy: endedByModerator ? "moderator" : "host",
        actorSubjectHash: subjectDidHash
      }
    }).catch(() => undefined);
    incCompleted("hangout_end");
    return reply.send({
      decision: "ALLOW",
      ended_by: endedByModerator ? "moderator" : "host",
      moderation_kill_switch: endedByModerator
    });
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
      return reply.code(503).send(
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
      return reply.code(503).send(
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
      return reply.code(503).send(
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
      return reply.code(503).send(
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
      return reply.code(503).send(
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
      return reply.code(503).send(
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
      return reply.code(503).send(
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
      return reply.code(503).send(
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
      return reply.code(503).send(
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
