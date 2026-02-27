import { useMemo, useState } from "react";
import { SignJWT, importJWK } from "jose";
import * as Registrar from "@hiero-did-sdk/registrar";
import type { OnboardingStrategy } from "@cuncta/shared";
import { fromBase64Url } from "./lib/encoding";
import { decodeDisclosure, sha256Base64Url } from "./lib/crypto";
import { generateKeypair, signPayload } from "./lib/ed25519";
import { buildHolderJwk, toBase58Multibase } from "./lib/keys";
import { presentSdJwt } from "./lib/sdjwt";

type Identity = {
  did: string;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  publicKeyMultibase: string;
};

type Credential = {
  vct: string;
  sdJwt: string;
};

type RequirementsResponse = {
  action: string;
  requirements: Array<{
    vct: string;
    label?: string;
    disclosures: string[];
    predicates?: Array<{ path: string; op: string; value?: unknown }>;
  }>;
  obligations?: Array<{ type: string }>;
  binding?: { mode: string; require: boolean };
  challenge: { nonce: string; audience: string; expires_at: string };
};

type SpaceDirectoryEntry = {
  space_id: string;
  slug: string;
  name: string;
  description: string;
  member_count: number;
  posting_requirement_summary: string;
};

type SpaceDetailResponse = {
  space: {
    space_id: string;
    slug: string;
    name: string;
    description: string;
    member_count: number;
  };
  policy_pack: {
    policy_pack_id: string;
    display_name: string;
    visibility: string;
  };
  requirements_summary: {
    join: Array<{ vct: string; label: string }>;
    post: Array<{ vct: string; label: string }>;
    moderate: Array<{ vct: string; label: string }>;
  };
};

type SpaceRulesPreview = {
  join_requirements: Array<{ vct: string; label: string }>;
  post_requirements: Array<{ vct: string; label: string }>;
  moderation_requirements: Array<{ vct: string; label: string }>;
  aura_thresholds?: { join?: string[]; post?: string[]; moderate?: string[] };
  governance?: {
    pack?: { policy_pack_id?: string; display_name?: string; visibility?: string };
    policy_versions?: {
      join?: { policy_id?: string | null; version?: number | null };
      post?: { policy_id?: string | null; version?: number | null };
      moderate?: { policy_id?: string | null; version?: number | null };
    };
    trust_floor?: { join?: string; post?: string; moderate?: string };
    pinning?: { join?: boolean; post?: boolean; moderate?: boolean };
  };
};

type SpaceGovernanceResponse = {
  policy_pack?: { policy_pack_id?: string; display_name?: string; visibility?: string };
  policy_versions?: {
    join?: { policy_id?: string | null; version?: number | null };
    post?: { policy_id?: string | null; version?: number | null };
    moderate?: { policy_id?: string | null; version?: number | null };
  };
  trust_floor?: { join?: string; post?: string; moderate?: string };
  pinning?: { join?: boolean; post?: boolean; moderate?: boolean };
};

type SpacePresenceStrip = {
  counts: { quiet: number; active: number; immersive: number };
  you?: { mode: string | null; active: boolean };
  crew?: { active_count?: number };
};

type SpaceRitualEntry = {
  ritual_id: string;
  title: string;
  description?: string;
  duration_minutes: number;
  starts_at: string;
  ends_at: string;
  participation_count: number;
  completion_count: number;
};

type SpaceCrewEntry = {
  crew_id: string;
  name: string;
  member_count: number;
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

type PulseSummary = {
  spaceId: string;
  cards: PulseCard[];
};

type PulsePreferences = {
  enabled: boolean;
  notifyHangouts: boolean;
  notifyCrews: boolean;
  notifyChallenges: boolean;
  notifyRankings: boolean;
  notifyStreaks: boolean;
};

type CommandPlanResponse = {
  action_plan: Array<{ intent: string; action_id: string; space_id?: string | null }>;
  required_capabilities: Array<{ vct: string; label?: string }>;
  ready_state: "READY" | "MISSING_PROOF" | "DENIED" | "NEEDS_REFINEMENT";
  deny_reason?: string | null;
  next_best_actions: string[];
  feeQuote?: {
    items?: Array<{
      asset?: {
        kind?: "HBAR" | "HTS";
        tokenId?: string | null;
        symbol?: string;
        decimals?: number;
      };
      amount?: string;
      purpose?: string;
    }>;
  } | null;
  feeScheduleFingerprint?: string | null;
  feeQuoteFingerprint?: string | null;
  paymentRequest?: {
    instructions?: Array<{
      to?: { accountId?: string };
      asset?: {
        kind?: "HBAR" | "HTS";
        tokenId?: string | null;
        symbol?: string;
        decimals?: number;
      };
      amount?: string;
      memo?: string;
      purpose?: string;
    }>;
  } | null;
  paymentRequestFingerprint?: string | null;
  paymentsConfigFingerprint?: string | null;
};

type FeedMode = "signal" | "flow";
type FlowTrustLens = "verified_only" | "trusted_creator" | "space_members";
type PostExplainResponse = {
  reasons: string[];
  trustStampSummary?: { tier?: string; capability?: string; domain?: string };
};

type CatalogEntry = {
  vct: string;
  display?: { title?: string; claims?: Array<{ path: string; label?: string }> };
};

type ServiceBases = {
  appGateway: string;
  didService: string;
  issuerService: string;
  verifierService: string;
  policyService: string;
};

const clampTtl = (value?: number) => {
  const base = Number.isFinite(value as number) ? Number(value) : 120;
  return Math.max(30, Math.min(600, base));
};

const readEnvNumber = (value?: string) => {
  if (!value) return undefined;
  const parsed = Number(value);
  return Number.isNaN(parsed) ? undefined : parsed;
};

const buildKbJwt = async (input: {
  nonce: string;
  audience: string;
  holderJwk: Record<string, unknown>;
  sdHash?: string;
  challengeExpiresAt?: string;
}) => {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const envTtl = readEnvNumber(import.meta.env.VITE_KBJWT_TTL_SECONDS);
  const baseTtl = clampTtl(envTtl);
  const expiresAt = input.challengeExpiresAt
    ? Math.floor((Date.parse(input.challengeExpiresAt) - Date.now()) / 1000)
    : baseTtl;
  const ttlSeconds = Math.max(1, Math.min(baseTtl, expiresAt));
  const holderKey = await importJWK(input.holderJwk as never, "EdDSA");
  const payload: Record<string, unknown> = {
    aud: input.audience,
    nonce: input.nonce,
    iat: nowSeconds,
    exp: nowSeconds + ttlSeconds,
    cnf: {
      jwk: {
        kty: "OKP",
        crv: "Ed25519",
        x: input.holderJwk.x,
        alg: "EdDSA"
      }
    }
  };
  if (input.sdHash) {
    payload.sd_hash = input.sdHash;
  }
  return new SignJWT(payload).setProtectedHeader({ alg: "EdDSA", typ: "kb+jwt" }).sign(holderKey);
};

const decodeDisclosureNames = (sdJwt: string) => {
  const parts = sdJwt.split("~");
  const disclosures = parts.slice(1).filter((value) => value.length > 0);
  return disclosures
    .map((disclosure) => {
      const parsed = decodeDisclosure(disclosure);
      const name = parsed[1];
      return typeof name === "string" ? name : null;
    })
    .filter((value): value is string => Boolean(value));
};

const storageKey = "web-demo:service-bases";
const checklistKey = "web-demo:checklist";

const defaultServiceBases = (): ServiceBases => ({
  appGateway: import.meta.env.VITE_APP_GATEWAY_BASE_URL ?? "http://localhost:3010",
  didService: import.meta.env.VITE_DID_SERVICE_BASE_URL ?? "http://localhost:3001",
  issuerService: import.meta.env.VITE_ISSUER_SERVICE_BASE_URL ?? "http://localhost:3002",
  verifierService: import.meta.env.VITE_VERIFIER_SERVICE_BASE_URL ?? "http://localhost:3003",
  policyService: import.meta.env.VITE_POLICY_SERVICE_BASE_URL ?? "http://localhost:3004"
});

const readStoredBases = (): Partial<ServiceBases> => {
  try {
    const raw = sessionStorage.getItem(storageKey);
    if (!raw) return {};
    return JSON.parse(raw) as Partial<ServiceBases>;
  } catch {
    return {};
  }
};

const readQueryOverrides = (): Partial<ServiceBases> => {
  const params = new URLSearchParams(window.location.search);
  const appGateway = params.get("gateway");
  const didService = params.get("did");
  const issuerService = params.get("issuer");
  const verifierService = params.get("verifier");
  const policyService = params.get("policy");
  return {
    ...(appGateway ? { appGateway } : {}),
    ...(didService ? { didService } : {}),
    ...(issuerService ? { issuerService } : {}),
    ...(verifierService ? { verifierService } : {}),
    ...(policyService ? { policyService } : {})
  };
};

const loadServiceBases = (): ServiceBases => {
  const defaults = defaultServiceBases();
  const stored = readStoredBases();
  const query = readQueryOverrides();
  const merged = { ...defaults, ...stored, ...query };
  if (Object.keys(query).length > 0) {
    sessionStorage.setItem(storageKey, JSON.stringify(merged));
  }
  return merged;
};

const loadChecklist = () => {
  try {
    const raw = sessionStorage.getItem(checklistKey);
    if (!raw) return Array.from({ length: 10 }, () => false);
    const parsed = JSON.parse(raw) as boolean[];
    if (!Array.isArray(parsed) || parsed.length !== 10) {
      return Array.from({ length: 10 }, () => false);
    }
    return parsed.map((value) => Boolean(value));
  } catch {
    return Array.from({ length: 10 }, () => false);
  }
};

const decodeJwtPayload = (token: string) => {
  try {
    const payloadSegment = token.split(".")[1];
    if (!payloadSegment) return null;
    const decoded = fromBase64Url(payloadSegment);
    const json = new TextDecoder().decode(decoded);
    return JSON.parse(json) as Record<string, unknown>;
  } catch {
    return null;
  }
};

const basicSdJwtCheck = (value: string) => value.includes(".") && value.includes("~");

const registrarModule = Registrar as unknown as { default?: typeof Registrar };
const registrar = registrarModule.default ?? Registrar;
type RegistrarProviders = Parameters<typeof registrar.generateCreateDIDRequest>[1];

const parseOnboardingStrategyList = (value?: string) => {
  if (!value) return [];
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry): entry is OnboardingStrategy => entry === "user_pays");
};
// CUNCTA supports self-funded onboarding only.

const allowedOnboardingStrategies = parseOnboardingStrategyList(
  import.meta.env.VITE_ONBOARDING_STRATEGY_ALLOWED
);
const hederaNetwork = import.meta.env.VITE_HEDERA_NETWORK ?? "testnet";
const isTestnet = hederaNetwork === "testnet";
const defaultOnboardingStrategy: OnboardingStrategy = "user_pays";
const initialOnboardingStrategy =
  allowedOnboardingStrategies.length > 0 &&
  !allowedOnboardingStrategies.includes(defaultOnboardingStrategy)
    ? allowedOnboardingStrategies[0]!
    : defaultOnboardingStrategy;

const socialCapabilityDescriptions: Record<string, string> = {
  "cuncta.social.account_active": "Base capability proving an active social account.",
  "cuncta.social.can_post": "Write capability used to create social posts.",
  "cuncta.social.can_comment": "Write capability used to create social replies.",
  "cuncta.social.trusted_creator": "Higher-trust creator capability from Aura progression.",
  "cuncta.social.space.member": "Space membership capability for joining space conversations.",
  "cuncta.social.space.poster": "Space posting capability for creating posts in a space.",
  "cuncta.social.space.moderator": "Moderation capability for handling reports and cases.",
  "cuncta.social.space.steward": "Steward capability with elevated social trust in a space.",
  "cuncta.sync.scroll_host": "Capability for hosting synchronized scroll groups in a space.",
  "cuncta.sync.listen_host": "Capability for hosting synchronized listen groups in a space.",
  "cuncta.sync.huddle_host": "Capability for hosting lightweight hangout control sessions.",
  "cuncta.social.ritual_creator": "Capability for creating recurring space challenges.",
  "cuncta.sync.session_participant":
    "Optional capability for participating in synchronized sessions."
};

const auraTierDescriptions: Record<string, string> = {
  none: "No social Aura capability claimed yet.",
  account_active: "Base social account capability is present.",
  can_post: "Posting capability is available.",
  trusted_creator: "Trusted creator tier is available."
};

const waitForDidResolution = async (
  didServiceBaseUrl: string,
  did: string,
  options: { maxAttempts?: number; intervalMs?: number } = {}
) => {
  const maxAttempts = options.maxAttempts ?? 60;
  const intervalMs = options.intervalMs ?? 4000;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      const response = await fetch(
        `${didServiceBaseUrl}/v1/dids/resolve/${encodeURIComponent(did)}`
      );
      if (response.ok) {
        const payload = (await response.json()) as { didDocument?: Record<string, unknown> };
        if (payload.didDocument && Object.keys(payload.didDocument).length > 0) {
          return;
        }
      }
    } catch {
      // ignore until timeout
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new Error(`Timed out waiting for DID resolution: ${did}`);
};

export default function App() {
  const [services, setServices] = useState<ServiceBases>(() => loadServiceBases());
  const [serviceDraft, setServiceDraft] = useState<ServiceBases>(services);
  const [showServiceEditor, setShowServiceEditor] = useState(false);
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [requirements, setRequirements] = useState<RequirementsResponse | null>(null);
  const [catalog, setCatalog] = useState<Record<string, CatalogEntry>>({});
  const [verificationResult, setVerificationResult] = useState<string>("");
  const [verificationReasons, setVerificationReasons] = useState<string[]>([]);
  const [onboardingStrategy, setOnboardingStrategy] = useState<OnboardingStrategy>(
    () => initialOnboardingStrategy
  );
  const [onboardingMethodUsed, setOnboardingMethodUsed] = useState<string>("sdk_key_entry");
  const [testnetDemoOnlyConfirmed, setTestnetDemoOnlyConfirmed] = useState(false);
  const [payerAccountId, setPayerAccountId] = useState("");
  const [payerPrivateKey, setPayerPrivateKey] = useState("");
  const [auraExplain, setAuraExplain] = useState<string>("");
  const [dsrToken, setDsrToken] = useState<string>("");
  const [dsrExport, setDsrExport] = useState<string>("");
  const [socialRequirements, setSocialRequirements] = useState<RequirementsResponse | null>(null);
  const [socialAction, setSocialAction] = useState<string>("social.post.create");
  const [socialDecision, setSocialDecision] = useState<string>("");
  const [socialReason, setSocialReason] = useState<string>("");
  const [socialHandle, setSocialHandle] = useState<string>("cuncta-demo");
  const [socialPostText, setSocialPostText] = useState<string>("Hello from CUNCTA Social.");
  const [socialReplyText, setSocialReplyText] = useState<string>("Thanks for sharing.");
  const [socialFollowDid, setSocialFollowDid] = useState<string>("");
  const [socialReportReason, setSocialReportReason] = useState<string>("abuse");
  const [socialFeed, setSocialFeed] = useState<Array<Record<string, unknown>>>([]);
  const [feedMode, setFeedMode] = useState<FeedMode>("signal");
  const [flowTrustLens, setFlowTrustLens] = useState<FlowTrustLens>("trusted_creator");
  const [flowSafetyStrict, setFlowSafetyStrict] = useState(false);
  const [postExplain, setPostExplain] = useState<PostExplainResponse | null>(null);
  const [postExplainId, setPostExplainId] = useState<string>("");
  const [spaceFeed, setSpaceFeed] = useState<Array<Record<string, unknown>>>([]);
  const [spaceFeedMode, setSpaceFeedMode] = useState<"signal" | "flow">("signal");
  const [spaceTrustLens, setSpaceTrustLens] = useState<FlowTrustLens>("trusted_creator");
  const [spaceSafetyStrict, setSpaceSafetyStrict] = useState(false);
  const [spaceGovernance, setSpaceGovernance] = useState<SpaceGovernanceResponse | null>(null);
  const [spaceModerationAudit, setSpaceModerationAudit] = useState<Array<Record<string, unknown>>>(
    []
  );
  const [spaceAnalytics, setSpaceAnalytics] = useState<string>("");
  const [socialFunnel, setSocialFunnel] = useState<string>("");
  const [spaces, setSpaces] = useState<SpaceDirectoryEntry[]>([]);
  const [spaceSearch, setSpaceSearch] = useState<string>("");
  const [selectedSpaceId, setSelectedSpaceId] = useState<string>("");
  const [spaceDetail, setSpaceDetail] = useState<SpaceDetailResponse | null>(null);
  const [spaceRules, setSpaceRules] = useState<SpaceRulesPreview | null>(null);
  const [spaceComposeText, setSpaceComposeText] = useState<string>("A new trust-aware post.");
  const [moderationCases, setModerationCases] = useState<
    Array<{ case_id: string; report_id: string; status: "OPEN" | "ACK" | "RESOLVED" }>
  >([]);
  const [spaceTrustHint, setSpaceTrustHint] = useState<string>("");
  const [spacePresenceStrip, setSpacePresenceStrip] = useState<SpacePresenceStrip | null>(null);
  const [spaceLeaderboard, setSpaceLeaderboard] = useState<Array<Record<string, unknown>>>([]);
  const [spaceTopStreaks, setSpaceTopStreaks] = useState<Array<Record<string, unknown>>>([]);
  const [spaceCrews, setSpaceCrews] = useState<SpaceCrewEntry[]>([]);
  const [spaceRituals, setSpaceRituals] = useState<SpaceRitualEntry[]>([]);
  const [pulseSummary, setPulseSummary] = useState<PulseSummary | null>(null);
  const [pulsePreferences, setPulsePreferences] = useState<PulsePreferences | null>(null);
  const [showPulsePanel, setShowPulsePanel] = useState(false);
  const [pulseExplainOpen, setPulseExplainOpen] = useState<Record<string, boolean>>({});
  const [spaceRitualTitle, setSpaceRitualTitle] = useState("10-minute drop");
  const [spaceRitualDescription, setSpaceRitualDescription] = useState(
    "Drop in with one contribution now."
  );
  const [spaceHuddleSessionId, setSpaceHuddleSessionId] = useState("");
  const [spaceHuddleParticipants, setSpaceHuddleParticipants] = useState<number>(0);
  const [spaceShowOnLeaderboard, setSpaceShowOnLeaderboard] = useState(false);
  const [status, setStatus] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [importText, setImportText] = useState("");
  const [importVct, setImportVct] = useState("");
  const [showChecklist, setShowChecklist] = useState(true);
  const [checklist, setChecklist] = useState<boolean[]>(() => loadChecklist());
  const [theme, setTheme] = useState<"day" | "night">("day");
  const [showCommandOrb, setShowCommandOrb] = useState(false);
  const [commandIntent, setCommandIntent] = useState("join hangout");
  const [commandPlan, setCommandPlan] = useState<CommandPlanResponse | null>(null);
  const [showCapabilityExplain, setShowCapabilityExplain] = useState<string>("");
  const [entSpaceId, setEntSpaceId] = useState<string>("");
  const [entEmojiPackId, setEntEmojiPackId] = useState<string>("");
  const [entSoundpackId, setEntSoundpackId] = useState<string>("");
  const [entScrollSessionId, setEntScrollSessionId] = useState<string>("");
  const [entListenSessionId, setEntListenSessionId] = useState<string>("");
  const [entScrollPermissionToken, setEntScrollPermissionToken] = useState<string>("");
  const [entListenPermissionToken, setEntListenPermissionToken] = useState<string>("");
  const [followHostScroll, setFollowHostScroll] = useState(true);
  const [syncHint, setSyncHint] = useState("");
  const [listenState, setListenState] = useState<string>("");
  const [presenceState, setPresenceState] = useState<string>("");
  const hasPulseCards = (pulseSummary?.cards?.length ?? 0) > 0;

  const holderJwk = useMemo(() => {
    if (!identity) return null;
    return buildHolderJwk(identity.privateKey, identity.publicKey);
  }, [identity]);

  const allowUserPays =
    allowedOnboardingStrategies.length === 0 || allowedOnboardingStrategies.includes("user_pays");
  const currentSocialRequirement = socialRequirements?.requirements[0];
  const currentAuraTier = useMemo(() => {
    if (credentials.some((cred) => cred.vct === "cuncta.social.trusted_creator"))
      return "trusted_creator";
    if (credentials.some((cred) => cred.vct === "cuncta.social.can_post")) return "can_post";
    if (credentials.some((cred) => cred.vct === "cuncta.social.account_active"))
      return "account_active";
    return "none";
  }, [credentials]);
  const hasCapability = (vct: string) => credentials.some((cred) => cred.vct === vct);
  const spaceRoleBadges = useMemo(() => {
    const roles: string[] = [];
    if (hasCapability("cuncta.social.space.member")) roles.push("Member");
    if (hasCapability("cuncta.social.space.poster")) roles.push("Poster");
    if (hasCapability("cuncta.social.space.moderator")) roles.push("Moderator");
    if (hasCapability("cuncta.social.trusted_creator")) roles.push("Trusted Creator");
    if (hasCapability("cuncta.social.space.steward")) roles.push("Steward");
    return roles;
  }, [credentials]);
  const canModerateInSpace =
    hasCapability("cuncta.social.space.moderator") || hasCapability("cuncta.social.space.steward");
  const auraSignalSummary = useMemo(() => {
    if (!auraExplain) return "Load aura explain to see contributing signals.";
    try {
      const parsed = JSON.parse(auraExplain) as {
        contributingSignals?: Array<{ signal?: string; weight?: number }>;
      };
      const signals = parsed.contributingSignals ?? [];
      if (signals.length === 0) return "No contributing signals reported yet.";
      return signals
        .slice(0, 3)
        .map((entry) => `${entry.signal ?? "signal"} (${String(entry.weight ?? 0)})`)
        .join(", ");
    } catch {
      return "Contributing signals summary unavailable.";
    }
  }, [auraExplain]);

  const createIdentity = async () => {
    setError("");
    setStatus("Creating identity...");
    try {
      const keypair = await generateKeypair();
      const publicKeyMultibase = toBase58Multibase(keypair.publicKey);
      if (!publicKeyMultibase.startsWith("z")) {
        throw new Error("publicKeyMultibase must start with 'z'.");
      }

      let did: string | null = null;
      {
        setOnboardingMethodUsed("sdk_key_entry");
        const hashPackApi = (window as unknown as Record<string, unknown>).hashpack as
          | {
              connect?: (args?: { network?: string }) => Promise<unknown>;
              sign?: (...args: unknown[]) => Promise<unknown>;
            }
          | undefined;
        if (hashPackApi?.connect) {
          setStatus("Attempting HashPack (Testnet)...");
          try {
            await hashPackApi.connect({ network: "testnet" });
            if (typeof hashPackApi.sign === "function") {
              setOnboardingMethodUsed("hashpack_direct");
              throw new Error(
                "HashPack detected, but direct DID signing flow is not enabled in this build. Falling back."
              );
            }
          } catch {
            setOnboardingMethodUsed("walletconnect_hashpack");
          }
        }

        if (!isTestnet || !testnetDemoOnlyConfirmed) {
          throw new Error(
            "SDK local key entry is demo-only. Confirm TESTNET DEMO ONLY to continue on testnet."
          );
        }

        const payerId = payerAccountId.trim();
        const payerKey = payerPrivateKey.trim();
        const effectivePayerId = payerId;
        const effectivePayerKey = payerKey;
        if (!effectivePayerId || !effectivePayerKey) {
          throw new Error("Self-funded onboarding requires payer credentials.");
        }
        setOnboardingMethodUsed("sdk_key_entry");
        setStatus("Submitting DID to Hedera (self-funded)...");
        const providers = {
          clientOptions: {
            network: "testnet" as unknown as string,
            accountId: effectivePayerId,
            privateKey: effectivePayerKey
          }
        } as RegistrarProviders;
        const createResult = await registrar.generateCreateDIDRequest(
          {
            multibasePublicKey: publicKeyMultibase
          },
          providers
        );
        const payloadToSign = createResult.signingRequest.serializedPayload;
        const signature = await signPayload(payloadToSign, keypair.privateKey);
        const submitResult = await registrar.submitCreateDIDRequest(
          {
            state: createResult.state as Registrar.SubmitCreateDIDRequestOptions["state"],
            signature,
            waitForDIDVisibility: false,
            visibilityTimeoutMs: 120_000
          },
          providers
        );
        did = submitResult.did;
      }

      if (!did) {
        throw new Error("DID creation failed");
      }
      setStatus("Pending network confirmation...");
      await waitForDidResolution(services.didService, did);
      setIdentity({
        did,
        publicKey: keypair.publicKey,
        privateKey: keypair.privateKey,
        publicKeyMultibase
      });
      setStatus("Identity created.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Identity creation failed");
    } finally {
      setStatus("");
    }
  };

  const requestDemoCredential = async () => {
    if (!identity) return;
    setError("");
    setStatus("Requesting demo credential...");
    try {
      // Self-funded: credentials via issuer directly (dev /v1/issue; prod would use OID4VCI)
      const response = await fetch(`${services.issuerService}/v1/issue`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          subjectDid: identity.did,
          vct: "cuncta.marketplace.seller_good_standing",
          claims: {
            seller_good_standing: true,
            domain: "marketplace",
            tier: "bronze",
            as_of: new Date().toISOString()
          }
        })
      });
      if (!response.ok) {
        throw new Error(await response.text());
      }
      const payload = await response.json();
      setCredentials((prev) => [
        ...prev.filter((cred) => cred.vct !== "cuncta.marketplace.seller_good_standing"),
        { vct: "cuncta.marketplace.seller_good_standing", sdJwt: payload.credential }
      ]);
      setStatus("Proof stored in browser session.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Proof request failed");
    } finally {
      setStatus("");
    }
  };

  const requestSocialCredential = async () => {
    if (!identity) return;
    setError("");
    setStatus("Requesting social account credential...");
    try {
      // Self-funded: credentials via issuer directly (dev /v1/issue; prod would use OID4VCI)
      const response = await fetch(`${services.issuerService}/v1/issue`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          subjectDid: identity.did,
          vct: "cuncta.social.account_active",
          claims: {
            account_active: true,
            domain: "social",
            as_of: new Date().toISOString()
          }
        })
      });
      if (!response.ok) {
        throw new Error(await response.text());
      }
      const payload = await response.json();
      setCredentials((prev) => [
        ...prev.filter((cred) => cred.vct !== "cuncta.social.account_active"),
        { vct: "cuncta.social.account_active", sdJwt: payload.credential }
      ]);
      setStatus("Social account proof stored in browser session.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Social proof request failed");
    } finally {
      setStatus("");
    }
  };

  const fetchRequirements = async (action: string) => {
    setError("");
    setStatus("Fetching requirements...");
    try {
      const response = await fetch(
        `${services.policyService}/v1/requirements?action=${encodeURIComponent(action)}`
      );
      if (!response.ok) {
        throw new Error(await response.text());
      }
      const payload = (await response.json()) as RequirementsResponse;
      setRequirements(payload);

      const vcts = payload.requirements.map((req) => req.vct);
      const entries = await Promise.all(
        vcts.map(async (vct) => {
          const res = await fetch(`${services.issuerService}/v1/catalog/credentials/${vct}`);
          if (!res.ok) return null;
          return (await res.json()) as CatalogEntry;
        })
      );
      const nextCatalog: Record<string, CatalogEntry> = {};
      entries.filter(Boolean).forEach((entry) => {
        nextCatalog[(entry as CatalogEntry).vct] = entry as CatalogEntry;
      });
      setCatalog(nextCatalog);
      return payload;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch requirements");
      return null;
    } finally {
      setStatus("");
    }
  };

  const verifyAction = async (action: string, payloadOverride?: RequirementsResponse | null) => {
    if (!identity || !holderJwk) return;
    const activeRequirements = payloadOverride ?? requirements;
    if (!activeRequirements) return;
    setError("");
    setStatus("Checking permission...");
    try {
      const requirement = activeRequirements.requirements[0];
      if (!requirement) {
        throw new Error("No requirement found");
      }
      const credential = credentials.find((cred) => cred.vct === requirement.vct);
      if (!credential) {
        throw new Error("Missing required proof");
      }
      const sdJwtPresentation = presentSdJwt(credential.sdJwt, requirement.disclosures);
      const sdHash = await sha256Base64Url(sdJwtPresentation);
      const kbJwt = await buildKbJwt({
        nonce: activeRequirements.challenge.nonce,
        audience: activeRequirements.challenge.audience,
        holderJwk,
        sdHash,
        challengeExpiresAt: activeRequirements.challenge.expires_at
      });
      const presentation = `${sdJwtPresentation}${kbJwt}`;
      const response = await fetch(
        `${services.appGateway}/v1/verify?action=${encodeURIComponent(action)}`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            presentation,
            nonce: activeRequirements.challenge.nonce,
            audience: activeRequirements.challenge.audience
          })
        }
      );
      const payload = await response.json();
      setVerificationResult(payload.decision ?? "UNKNOWN");
      setVerificationReasons(payload.reasons ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification failed");
    } finally {
      setStatus("");
    }
  };

  const fetchSocialRequirements = async (action: string, spaceId?: string) => {
    setError("");
    setStatus("Loading social policy requirements...");
    try {
      const url = new URL("/v1/social/requirements", services.appGateway);
      url.searchParams.set("action", action);
      if (spaceId) {
        url.searchParams.set("space_id", spaceId);
      }
      const response = await fetch(url.toString());
      if (!response.ok) {
        throw new Error(await response.text());
      }
      const payload = (await response.json()) as RequirementsResponse;
      setSocialRequirements(payload);
      setSocialAction(action);
      return payload;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch social requirements");
      return null;
    } finally {
      setStatus("");
    }
  };

  const buildSocialPresentationPayload = async (
    payload: RequirementsResponse
  ): Promise<{ presentation: string; nonce: string; audience: string } | null> => {
    if (!holderJwk) return null;
    const requirement = payload.requirements[0];
    if (!requirement) {
      setError("No social requirement found.");
      return null;
    }
    const credential = credentials.find((cred) => cred.vct === requirement.vct);
    if (!credential) {
      setError(`Missing required proof: ${requirement.vct}`);
      return null;
    }
    const sdJwtPresentation = presentSdJwt(credential.sdJwt, requirement.disclosures);
    const sdHash = await sha256Base64Url(sdJwtPresentation);
    const kbJwt = await buildKbJwt({
      nonce: payload.challenge.nonce,
      audience: payload.challenge.audience,
      holderJwk,
      sdHash,
      challengeExpiresAt: payload.challenge.expires_at
    });
    const presentation = `${sdJwtPresentation}${kbJwt}`;
    return {
      presentation,
      nonce: payload.challenge.nonce,
      audience: payload.challenge.audience
    };
  };

  const createSocialProfile = async () => {
    if (!identity) return;
    setError("");
    setStatus("Checking policy and creating social profile...");
    try {
      const req = (await fetchSocialRequirements("social.profile.create")) ?? socialRequirements;
      if (!req) return;
      const proof = await buildSocialPresentationPayload(req);
      if (!proof) return;
      const response = await fetch(`${services.appGateway}/v1/social/profile/create`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          subjectDid: identity.did,
          handle: socialHandle,
          ...proof
        })
      });
      const payload = (await response.json().catch(() => ({}))) as {
        decision?: string;
        reason?: string;
        message?: string;
      };
      setSocialDecision(payload.decision ?? (response.ok ? "ALLOW" : "DENY"));
      setSocialReason(
        payload.reason ??
          payload.message ??
          (response.ok ? "Profile created by policy allow." : "Profile denied by policy.")
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Create profile failed");
    } finally {
      setStatus("");
    }
  };

  const runEntertainmentAction = async (
    actionId: string,
    path: string,
    body: Record<string, unknown>,
    options: { spaceId?: string; method?: "POST" | "GET" } = {}
  ) => {
    if (!identity) return null;
    const req = await fetchSocialRequirements(actionId, options.spaceId);
    if (!req) return null;
    const proof = await buildSocialPresentationPayload(req);
    if (!proof) return null;
    const response = await fetch(`${services.appGateway}${path}`, {
      method: options.method ?? "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ subjectDid: identity.did, ...body, ...proof })
    });
    const payload = (await response.json().catch(() => ({}))) as Record<string, unknown>;
    setSocialDecision(String(payload.decision ?? (response.ok ? "ALLOW" : "DENY")));
    setSocialReason(String(payload.message ?? ""));
    if (!response.ok) {
      throw new Error(String(payload.message ?? "Action denied"));
    }
    return payload;
  };

  const openSyncStream = (
    sessionId: string,
    permissionToken: string,
    onEvent: (event: Record<string, unknown>) => void
  ) => {
    const base = new URL(services.appGateway);
    const protocol = base.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${base.host}/v1/social/sync/session/${encodeURIComponent(sessionId)}/stream?permission_token=${encodeURIComponent(permissionToken)}`;
    const socket = new WebSocket(wsUrl);
    socket.onmessage = (message) => {
      try {
        const parsed = JSON.parse(String(message.data)) as Record<string, unknown>;
        onEvent(parsed);
      } catch {
        // ignore non-json messages
      }
    };
    socket.onerror = () => {
      setSyncHint(
        "Sync stream unavailable via gateway. In dev, connect directly to social-service stream endpoint."
      );
    };
    return socket;
  };

  const subscribeScrollStream = (sessionId: string, permissionToken: string) => {
    const socket = openSyncStream(sessionId, permissionToken, (event) => {
      if (String(event.type) !== "sync_event") return;
      const payload = (event.event as Record<string, unknown> | undefined)?.payload_json as
        | Record<string, unknown>
        | undefined;
      const y = Number(payload?.scrollY ?? 0);
      if (followHostScroll) {
        window.scrollTo({ top: Number.isFinite(y) ? y : 0, behavior: "smooth" });
        setSyncHint("Following host scroll in real time.");
      } else {
        setSyncHint("Sync available - enable follow host to jump to latest position.");
      }
    });
    return socket;
  };

  const subscribeListenStream = (sessionId: string, permissionToken: string) => {
    return openSyncStream(sessionId, permissionToken, (event) => {
      if (String(event.type) !== "sync_event") return;
      const payload = (event.event as Record<string, unknown> | undefined)?.payload_json;
      setListenState(JSON.stringify(payload ?? {}, null, 2));
    });
  };

  const explainCapability = async (actionId: string, spaceId?: string) => {
    const req = await fetchSocialRequirements(actionId, spaceId);
    const requirement = req?.requirements?.[0];
    if (!requirement) {
      setShowCapabilityExplain("No requirement metadata available.");
      return;
    }
    const has = hasCapability(requirement.vct);
    setShowCapabilityExplain(
      `Requires ${requirement.label ?? requirement.vct}. You ${has ? "have" : "do not have"} it. Aura tier: ${currentAuraTier}.`
    );
  };

  const loadPresenceState = async (spaceId: string) => {
    const response = await fetch(
      `${services.appGateway}/v1/social/presence/state?spaceId=${encodeURIComponent(spaceId)}`
    );
    if (!response.ok) throw new Error(await response.text());
    setPresenceState(JSON.stringify(await response.json(), null, 2));
  };

  const createSocialPost = async () => {
    if (!identity) return;
    setError("");
    setStatus("Checking policy and creating social post...");
    try {
      const req = (await fetchSocialRequirements("social.post.create")) ?? socialRequirements;
      if (!req) return;
      const proof = await buildSocialPresentationPayload(req);
      if (!proof) return;
      const response = await fetch(`${services.appGateway}/v1/social/post`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          subjectDid: identity.did,
          content: socialPostText,
          visibility: "public",
          ...proof
        })
      });
      const payload = (await response.json().catch(() => ({}))) as {
        decision?: string;
        reason?: string;
        message?: string;
      };
      setSocialDecision(payload.decision ?? (response.ok ? "ALLOW" : "DENY"));
      setSocialReason(
        payload.reason ??
          payload.message ??
          (response.ok ? "Post created by policy allow." : "Post denied by policy.")
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Create post failed");
    } finally {
      setStatus("");
    }
  };

  const createSocialReply = async () => {
    if (!identity) return;
    const firstPost = socialFeed[0];
    const postId = String(firstPost?.post_id ?? "");
    if (!postId) {
      setError("Load feed first to pick a post for reply.");
      return;
    }
    setError("");
    setStatus("Checking policy and creating social reply...");
    try {
      const req = (await fetchSocialRequirements("social.reply.create")) ?? socialRequirements;
      if (!req) return;
      const proof = await buildSocialPresentationPayload(req);
      if (!proof) return;
      const response = await fetch(`${services.appGateway}/v1/social/reply`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          subjectDid: identity.did,
          postId,
          content: socialReplyText,
          ...proof
        })
      });
      const payload = (await response.json().catch(() => ({}))) as {
        decision?: string;
        message?: string;
      };
      setSocialDecision(payload.decision ?? (response.ok ? "ALLOW" : "DENY"));
      setSocialReason(
        payload.message ??
          (response.ok ? "Reply created by policy allow." : "Reply denied by policy.")
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Create reply failed");
    } finally {
      setStatus("");
    }
  };

  const createSocialFollow = async () => {
    if (!identity) return;
    if (!socialFollowDid.trim()) {
      setError("Enter a DID to follow.");
      return;
    }
    setError("");
    setStatus("Checking policy and creating follow...");
    try {
      const req = (await fetchSocialRequirements("social.follow.create")) ?? socialRequirements;
      if (!req) return;
      const proof = await buildSocialPresentationPayload(req);
      if (!proof) return;
      const response = await fetch(`${services.appGateway}/v1/social/follow`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          subjectDid: identity.did,
          followeeDid: socialFollowDid,
          ...proof
        })
      });
      const payload = (await response.json().catch(() => ({}))) as {
        decision?: string;
        message?: string;
      };
      setSocialDecision(payload.decision ?? (response.ok ? "ALLOW" : "DENY"));
      setSocialReason(
        payload.message ?? (response.ok ? "Follow saved." : "Follow denied by policy.")
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Follow failed");
    } finally {
      setStatus("");
    }
  };

  const createSocialReport = async () => {
    if (!identity) return;
    const firstPost = socialFeed[0];
    const targetPostId = String(firstPost?.post_id ?? "");
    if (!targetPostId) {
      setError("Load feed first to report a post.");
      return;
    }
    setError("");
    setStatus("Submitting safety report...");
    try {
      const req = (await fetchSocialRequirements("social.report.create")) ?? socialRequirements;
      if (!req) return;
      const proof = await buildSocialPresentationPayload(req);
      if (!proof) return;
      const response = await fetch(`${services.appGateway}/v1/social/report`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          subjectDid: identity.did,
          targetPostId,
          reasonCode: socialReportReason,
          ...proof
        })
      });
      const payload = (await response.json().catch(() => ({}))) as {
        decision?: string;
        message?: string;
      };
      setSocialDecision(payload.decision ?? (response.ok ? "ALLOW" : "DENY"));
      setSocialReason(
        payload.message ?? (response.ok ? "Report captured." : "Report denied by policy.")
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Report failed");
    } finally {
      setStatus("");
    }
  };

  const loadSocialFeed = async () => {
    setError("");
    setStatus("Loading social feed...");
    try {
      const query = identity?.did ? `?viewerDid=${encodeURIComponent(identity.did)}` : "";
      const response = await fetch(`${services.appGateway}/v1/social/feed${query}`);
      if (!response.ok) {
        throw new Error(await response.text());
      }
      const payload = (await response.json()) as { posts?: Array<Record<string, unknown>> };
      setSocialFeed(payload.posts ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Feed load failed");
    } finally {
      setStatus("");
    }
  };

  const loadFlowFeed = async () => {
    setError("");
    setStatus("Loading flow feed...");
    try {
      const url = new URL("/v1/social/feed/flow", services.appGateway);
      if (identity?.did) {
        url.searchParams.set("viewerDid", identity.did);
      }
      url.searchParams.set("trust", flowTrustLens);
      if (flowSafetyStrict) {
        url.searchParams.set("safety", "strict");
      }
      const response = await fetch(url.toString());
      if (!response.ok) {
        throw new Error(await response.text());
      }
      const payload = (await response.json()) as { posts?: Array<Record<string, unknown>> };
      setSocialFeed(payload.posts ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Flow feed load failed");
    } finally {
      setStatus("");
    }
  };

  const loadActiveFeed = async () => {
    if (feedMode === "flow") {
      await loadFlowFeed();
      return;
    }
    await loadSocialFeed();
  };

  const explainPost = async (postId: string) => {
    setError("");
    setStatus("Loading post explanation...");
    try {
      const url = new URL(
        `/v1/social/post/${encodeURIComponent(postId)}/explain`,
        services.appGateway
      );
      if (identity?.did) {
        url.searchParams.set("viewerDid", identity.did);
      }
      url.searchParams.set("feedMode", feedMode);
      if (feedMode === "flow") {
        url.searchParams.set("trust", flowTrustLens);
        if (flowSafetyStrict) {
          url.searchParams.set("safety", "strict");
        }
      }
      const response = await fetch(url.toString());
      if (!response.ok) {
        throw new Error(await response.text());
      }
      setPostExplain((await response.json()) as PostExplainResponse);
      setPostExplainId(postId);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Explain request failed");
    } finally {
      setStatus("");
    }
  };

  const loadSocialFunnel = async () => {
    setError("");
    setStatus("Loading trust funnel metrics...");
    try {
      const response = await fetch(`${services.appGateway}/v1/social/funnel`);
      if (!response.ok) {
        throw new Error(await response.text());
      }
      const payload = (await response.json()) as Record<string, unknown>;
      setSocialFunnel(JSON.stringify(payload, null, 2));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Funnel load failed");
    } finally {
      setStatus("");
    }
  };

  const loadSpaces = async () => {
    setError("");
    setStatus("Loading spaces directory...");
    try {
      const url = new URL("/v1/social/spaces", services.appGateway);
      if (spaceSearch.trim()) {
        url.searchParams.set("search", spaceSearch.trim());
      }
      url.searchParams.set("limit", "25");
      const response = await fetch(url.toString());
      if (!response.ok) {
        throw new Error(await response.text());
      }
      const payload = (await response.json()) as { spaces?: SpaceDirectoryEntry[] };
      setSpaces(payload.spaces ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load spaces");
    } finally {
      setStatus("");
    }
  };

  const loadSpaceFeed = async (spaceId: string) => {
    const query = identity?.did ? `&viewerDid=${encodeURIComponent(identity.did)}` : "";
    const response = await fetch(
      `${services.appGateway}/v1/social/space/feed?spaceId=${encodeURIComponent(spaceId)}${query}`
    );
    if (!response.ok) {
      throw new Error(await response.text());
    }
    const payload = (await response.json()) as { posts?: Array<Record<string, unknown>> };
    setSpaceFeed(payload.posts ?? []);
  };

  const loadSpaceFlow = async (spaceId: string) => {
    const url = new URL("/v1/social/space/flow", services.appGateway);
    url.searchParams.set("spaceId", spaceId);
    url.searchParams.set("trust", spaceTrustLens);
    if (identity?.did) {
      url.searchParams.set("viewerDid", identity.did);
    }
    if (spaceSafetyStrict) {
      url.searchParams.set("safety", "strict");
    }
    const response = await fetch(url.toString());
    if (!response.ok) {
      throw new Error(await response.text());
    }
    const payload = (await response.json()) as { posts?: Array<Record<string, unknown>> };
    setSpaceFeed(payload.posts ?? []);
  };

  const loadActiveSpaceFeed = async (spaceId: string) => {
    if (spaceFeedMode === "flow") {
      await loadSpaceFlow(spaceId);
      return;
    }
    await loadSpaceFeed(spaceId);
  };

  const loadSpaceGovernance = async (spaceId: string) => {
    const response = await fetch(
      `${services.appGateway}/v1/social/spaces/${encodeURIComponent(spaceId)}/governance`
    );
    if (!response.ok) {
      throw new Error(await response.text());
    }
    setSpaceGovernance((await response.json()) as SpaceGovernanceResponse);
  };

  const openSpace = async (spaceId: string) => {
    setError("");
    setStatus("Opening space...");
    try {
      const [detailResponse, rulesResponse] = await Promise.all([
        fetch(`${services.appGateway}/v1/social/spaces/${encodeURIComponent(spaceId)}`),
        fetch(`${services.appGateway}/v1/social/spaces/${encodeURIComponent(spaceId)}/rules`)
      ]);
      if (!detailResponse.ok) {
        throw new Error(await detailResponse.text());
      }
      if (!rulesResponse.ok) {
        throw new Error(await rulesResponse.text());
      }
      setSelectedSpaceId(spaceId);
      setEntSpaceId(spaceId);
      setShowPulsePanel(false);
      setPulseExplainOpen({});
      setSpaceDetail((await detailResponse.json()) as SpaceDetailResponse);
      setSpaceRules((await rulesResponse.json()) as SpaceRulesPreview);
      await loadActiveSpaceFeed(spaceId);
      await loadSpaceGovernance(spaceId);
      await loadPresenceStrip(spaceId);
      await loadSpaceLeaderboard(spaceId);
      await loadSpaceTopStreaks(spaceId);
      await loadSpaceCrews(spaceId);
      await loadSpaceRituals(spaceId);
      await loadPulse(spaceId);
      await loadPulsePreferences(spaceId);
      if (canModerateInSpace && identity) {
        await loadModerationCases(spaceId);
        await loadSpaceModerationAudit(spaceId);
      } else {
        setModerationCases([]);
        setSpaceModerationAudit([]);
      }
      await loadSpaceAnalytics(spaceId);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to open space");
    } finally {
      setStatus("");
    }
  };

  const joinSpace = async (spaceId: string) => {
    if (!identity) return;
    setError("");
    setStatus("Joining space...");
    try {
      const req = await fetchSocialRequirements("social.space.join", spaceId);
      if (!req) return;
      const proof = await buildSocialPresentationPayload(req);
      if (!proof) return;
      const response = await fetch(`${services.appGateway}/v1/social/space/join`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          subjectDid: identity.did,
          spaceId,
          ...proof
        })
      });
      const payload = (await response.json().catch(() => ({}))) as {
        decision?: string;
        message?: string;
      };
      setSocialDecision(payload.decision ?? (response.ok ? "ALLOW" : "DENY"));
      setSocialReason(
        payload.message ?? (response.ok ? "Joined the space." : "Join denied by policy.")
      );
      if (response.ok) {
        await openSpace(spaceId);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Join failed");
    } finally {
      setStatus("");
    }
  };

  const createSpacePost = async (spaceId: string) => {
    if (!identity) return;
    setError("");
    setSpaceTrustHint("");
    setStatus("Posting inside space...");
    try {
      const req = await fetchSocialRequirements("social.space.post.create", spaceId);
      if (!req) return;
      const proof = await buildSocialPresentationPayload(req);
      if (!proof) return;
      const response = await fetch(`${services.appGateway}/v1/social/space/post`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          subjectDid: identity.did,
          spaceId,
          content: spaceComposeText,
          ...proof
        })
      });
      const payload = (await response.json().catch(() => ({}))) as {
        decision?: string;
        message?: string;
      };
      const decision = payload.decision ?? (response.ok ? "ALLOW" : "DENY");
      setSocialDecision(decision);
      setSocialReason(
        payload.message ??
          (response.ok ? "Space post published." : "Denied. Capability requirement not met.")
      );
      if (!response.ok) {
        const requirementLabel =
          req.requirements[0]?.label ?? req.requirements[0]?.vct ?? "required capability";
        setSpaceTrustHint(
          `Missing requirement: ${requirementLabel}. Aura tier: ${currentAuraTier}. Use the Trust Panel for explainers.`
        );
      } else {
        await loadSpaceFeed(spaceId);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Space post failed");
    } finally {
      setStatus("");
    }
  };

  const loadModerationCases = async (spaceId: string) => {
    if (!identity || !canModerateInSpace) return;
    const requirements = await fetchSocialRequirements("social.space.moderate", spaceId);
    if (!requirements) return;
    const proof = await buildSocialPresentationPayload(requirements);
    if (!proof) return;
    const url = new URL(
      `/v1/social/spaces/${encodeURIComponent(spaceId)}/moderation/cases`,
      services.appGateway
    );
    url.searchParams.set("subjectDid", identity.did);
    url.searchParams.set("presentation", proof.presentation);
    url.searchParams.set("nonce", proof.nonce);
    url.searchParams.set("audience", proof.audience);
    const response = await fetch(url.toString());
    if (!response.ok) {
      throw new Error(await response.text());
    }
    const payload = (await response.json()) as {
      cases?: Array<{ case_id: string; report_id: string; status: "OPEN" | "ACK" | "RESOLVED" }>;
    };
    setModerationCases(payload.cases ?? []);
  };

  const loadSpaceModerationAudit = async (spaceId: string) => {
    if (!identity || !canModerateInSpace) return;
    const requirements = await fetchSocialRequirements("social.space.moderate", spaceId);
    if (!requirements) return;
    const proof = await buildSocialPresentationPayload(requirements);
    if (!proof) return;
    const url = new URL(
      `/v1/social/spaces/${encodeURIComponent(spaceId)}/moderation/audit`,
      services.appGateway
    );
    url.searchParams.set("subjectDid", identity.did);
    url.searchParams.set("presentation", proof.presentation);
    url.searchParams.set("nonce", proof.nonce);
    url.searchParams.set("audience", proof.audience);
    const response = await fetch(url.toString());
    if (!response.ok) {
      throw new Error(await response.text());
    }
    const payload = (await response.json()) as { actions?: Array<Record<string, unknown>> };
    setSpaceModerationAudit(payload.actions ?? []);
  };

  const loadSpaceAnalytics = async (spaceId: string) => {
    const response = await fetch(
      `${services.appGateway}/v1/social/spaces/${encodeURIComponent(spaceId)}/analytics`
    );
    if (!response.ok) {
      throw new Error(await response.text());
    }
    setSpaceAnalytics(JSON.stringify(await response.json(), null, 2));
  };

  const loadPresenceStrip = async (spaceId: string) => {
    const url = new URL(
      `/v1/social/spaces/${encodeURIComponent(spaceId)}/presence`,
      services.appGateway
    );
    if (identity?.did) {
      url.searchParams.set("subjectDid", identity.did);
    }
    const response = await fetch(url.toString());
    if (!response.ok) {
      throw new Error(await response.text());
    }
    const payload = (await response.json()) as SpacePresenceStrip;
    setSpacePresenceStrip(payload);
  };

  const loadPulse = async (spaceId: string) => {
    const url = new URL(
      `/v1/social/spaces/${encodeURIComponent(spaceId)}/pulse`,
      services.appGateway
    );
    if (identity?.did) {
      url.searchParams.set("subjectDid", identity.did);
    }
    const response = await fetch(url.toString());
    if (!response.ok) {
      throw new Error(await response.text());
    }
    const payload = (await response.json()) as PulseSummary;
    setPulseSummary(payload);
  };

  const loadPulsePreferences = async (spaceId: string) => {
    const url = new URL(
      `/v1/social/spaces/${encodeURIComponent(spaceId)}/pulse/preferences`,
      services.appGateway
    );
    if (identity?.did) {
      url.searchParams.set("subjectDid", identity.did);
    }
    const response = await fetch(url.toString());
    if (!response.ok) {
      throw new Error(await response.text());
    }
    const payload = (await response.json()) as { preferences?: PulsePreferences };
    setPulsePreferences(payload.preferences ?? null);
  };

  const updatePulsePreference = async (
    spaceId: string,
    patch: Partial<Omit<PulsePreferences, "enabled">> & { enabled?: boolean }
  ) => {
    if (!identity) return;
    const req = await fetchSocialRequirements("presence.ping", spaceId);
    if (!req) return;
    const proof = await buildSocialPresentationPayload(req);
    if (!proof) return;
    const response = await fetch(
      `${services.appGateway}/v1/social/spaces/${encodeURIComponent(spaceId)}/pulse/preferences`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          subjectDid: identity.did,
          ...patch,
          ...proof
        })
      }
    );
    if (!response.ok) {
      throw new Error(await response.text());
    }
    const payload = (await response.json()) as { preferences?: PulsePreferences };
    setPulsePreferences(payload.preferences ?? null);
    await loadPulse(spaceId);
  };

  const togglePulseExplain = (cardType: PulseCard["type"]) => {
    setPulseExplainOpen((prev) => ({ ...prev, [cardType]: !prev[cardType] }));
  };

  const runCommandPlan = async () => {
    setError("");
    setStatus("Planning command...");
    const response = await fetch(`${services.appGateway}/v1/command/plan`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intent: commandIntent,
        spaceId: selectedSpaceId || undefined
      })
    });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    const payload = (await response.json()) as CommandPlanResponse;
    setCommandPlan(payload);
    setStatus(payload.ready_state === "READY" ? "Command ready." : "Command needs more proof.");
  };

  const runPulseCta = async (spaceId: string, card: PulseCard) => {
    if (card.route === "open_crews") {
      await loadSpaceCrews(spaceId);
      return;
    }
    if (card.route === "join_hangout") {
      if (card.sessionId) {
        await joinHuddleSession(spaceId, card.sessionId);
      }
      return;
    }
    if (card.route === "open_challenges" || card.route === "complete_challenge") {
      await loadSpaceRituals(spaceId);
      return;
    }
    if (card.route === "open_rankings") {
      await Promise.all([loadSpaceLeaderboard(spaceId), loadSpaceTopStreaks(spaceId)]);
      return;
    }
    if (card.route === "compose_post") {
      await createSpacePost(spaceId);
    }
  };

  const pingPresence = async (
    spaceId: string,
    mode: "quiet" | "active" | "immersive" = "active"
  ) => {
    if (!identity) return;
    const req = await fetchSocialRequirements("presence.ping", spaceId);
    if (!req) return;
    const proof = await buildSocialPresentationPayload(req);
    if (!proof) return;
    const response = await fetch(
      `${services.appGateway}/v1/social/spaces/${encodeURIComponent(spaceId)}/presence/ping`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          subjectDid: identity.did,
          mode,
          ...proof
        })
      }
    );
    if (!response.ok) {
      throw new Error(await response.text());
    }
    await Promise.all([loadPresenceStrip(spaceId), loadPulse(spaceId)]);
  };

  const updateSpaceVisibility = async (spaceId: string, showOnLeaderboard: boolean) => {
    if (!identity) return;
    const req = await fetchSocialRequirements("presence.ping", spaceId);
    if (!req) return;
    const proof = await buildSocialPresentationPayload(req);
    if (!proof) return;
    const response = await fetch(
      `${services.appGateway}/v1/social/spaces/${encodeURIComponent(spaceId)}/profile/visibility`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          subjectDid: identity.did,
          showOnLeaderboard,
          showOnPresence: false,
          ...proof
        })
      }
    );
    if (!response.ok) {
      throw new Error(await response.text());
    }
    setSpaceShowOnLeaderboard(showOnLeaderboard);
    await loadSpaceLeaderboard(spaceId);
  };

  const loadSpaceLeaderboard = async (spaceId: string) => {
    const response = await fetch(
      `${services.appGateway}/v1/social/spaces/${encodeURIComponent(spaceId)}/rankings?type=contributors`
    );
    if (!response.ok) {
      throw new Error(await response.text());
    }
    const payload = (await response.json()) as { rows?: Array<Record<string, unknown>> };
    setSpaceLeaderboard(payload.rows ?? []);
  };

  const loadSpaceTopStreaks = async (spaceId: string) => {
    const response = await fetch(
      `${services.appGateway}/v1/social/spaces/${encodeURIComponent(spaceId)}/rankings?type=streaks`
    );
    if (!response.ok) {
      throw new Error(await response.text());
    }
    const payload = (await response.json()) as { rows?: Array<Record<string, unknown>> };
    setSpaceTopStreaks(payload.rows ?? []);
  };

  const loadSpaceCrews = async (spaceId: string) => {
    const response = await fetch(
      `${services.appGateway}/v1/social/spaces/${encodeURIComponent(spaceId)}/crews`
    );
    if (!response.ok) {
      throw new Error(await response.text());
    }
    const payload = (await response.json()) as { crews?: SpaceCrewEntry[] };
    setSpaceCrews(payload.crews ?? []);
  };

  const loadSpaceRituals = async (spaceId: string) => {
    const response = await fetch(
      `${services.appGateway}/v1/social/spaces/${encodeURIComponent(spaceId)}/rituals/active`
    );
    if (!response.ok) {
      throw new Error(await response.text());
    }
    const payload = (await response.json()) as { rituals?: SpaceRitualEntry[] };
    setSpaceRituals(payload.rituals ?? []);
  };

  const createRitual = async (spaceId: string) => {
    if (!identity) return;
    const req = await fetchSocialRequirements("ritual.create", spaceId);
    if (!req) return;
    const proof = await buildSocialPresentationPayload(req);
    if (!proof) return;
    const response = await fetch(`${services.appGateway}/v1/social/ritual/create`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        subjectDid: identity.did,
        spaceId,
        title: spaceRitualTitle,
        description: spaceRitualDescription,
        durationMinutes: 10,
        ...proof
      })
    });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    await Promise.all([loadSpaceRituals(spaceId), loadPulse(spaceId)]);
  };

  const participateRitual = async (spaceId: string, ritualId: string) => {
    if (!identity) return;
    const req = await fetchSocialRequirements("ritual.participate", spaceId);
    if (!req) return;
    const proof = await buildSocialPresentationPayload(req);
    if (!proof) return;
    const response = await fetch(`${services.appGateway}/v1/social/ritual/participate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        subjectDid: identity.did,
        ritualId,
        spaceId,
        ...proof
      })
    });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    await Promise.all([loadSpaceRituals(spaceId), loadPulse(spaceId)]);
  };

  const completeRitual = async (spaceId: string, ritualId: string) => {
    if (!identity) return;
    const req = await fetchSocialRequirements("ritual.complete", spaceId);
    if (!req) return;
    const proof = await buildSocialPresentationPayload(req);
    if (!proof) return;
    const response = await fetch(`${services.appGateway}/v1/social/ritual/complete`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        subjectDid: identity.did,
        ritualId,
        spaceId,
        ...proof
      })
    });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    await Promise.all([
      loadSpaceRituals(spaceId),
      loadSpaceLeaderboard(spaceId),
      loadSpaceTopStreaks(spaceId),
      loadPulse(spaceId)
    ]);
  };

  const createHuddleSession = async (spaceId: string) => {
    if (!identity) return;
    const req = await fetchSocialRequirements("sync.hangout.create_session", spaceId);
    if (!req) return;
    const proof = await buildSocialPresentationPayload(req);
    if (!proof) return;
    const response = await fetch(`${services.appGateway}/v1/social/sync/hangout/create_session`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        subjectDid: identity.did,
        spaceId,
        ...proof
      })
    });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    const payload = (await response.json()) as { sessionId?: string; participant_count?: number };
    setSpaceHuddleSessionId(String(payload.sessionId ?? ""));
    setSpaceHuddleParticipants(Number(payload.participant_count ?? 0));
    await loadPulse(spaceId);
  };

  const joinHuddleSession = async (spaceId: string, sessionId: string) => {
    if (!identity || !sessionId) return;
    const req = await fetchSocialRequirements("sync.hangout.join_session", spaceId);
    if (!req) return;
    const proof = await buildSocialPresentationPayload(req);
    if (!proof) return;
    const response = await fetch(`${services.appGateway}/v1/social/sync/hangout/join_session`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        subjectDid: identity.did,
        sessionId,
        spaceId,
        ...proof
      })
    });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    const payload = (await response.json()) as { participant_count?: number };
    setSpaceHuddleParticipants(Number(payload.participant_count ?? 0));
    await loadPulse(spaceId);
  };

  const endHuddleSession = async (spaceId: string, sessionId: string) => {
    if (!identity || !sessionId) return;
    const req = await fetchSocialRequirements("sync.hangout.end_session", spaceId);
    if (!req) return;
    const proof = await buildSocialPresentationPayload(req);
    if (!proof) return;
    const response = await fetch(`${services.appGateway}/v1/social/sync/hangout/end_session`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        subjectDid: identity.did,
        sessionId,
        spaceId,
        reasonCode: "manual_end",
        ...proof
      })
    });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    setSpaceHuddleSessionId("");
    setSpaceHuddleParticipants(0);
    await loadPulse(spaceId);
  };

  const resolveModerationCase = async (spaceId: string, caseId: string) => {
    if (!identity || !canModerateInSpace) return;
    setError("");
    setStatus("Resolving moderation case...");
    try {
      const requirements = await fetchSocialRequirements("social.space.moderate", spaceId);
      if (!requirements) return;
      const proof = await buildSocialPresentationPayload(requirements);
      if (!proof) return;
      const response = await fetch(
        `${services.appGateway}/v1/social/spaces/${encodeURIComponent(spaceId)}/moderation/cases/${encodeURIComponent(caseId)}/resolve`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            subjectDid: identity.did,
            presentation: proof.presentation,
            nonce: proof.nonce,
            audience: proof.audience,
            anchor: true
          })
        }
      );
      if (!response.ok) {
        throw new Error(await response.text());
      }
      await loadModerationCases(spaceId);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Resolve failed");
    } finally {
      setStatus("");
    }
  };

  const simulateAura = async () => {
    const payload = await fetchRequirements("dev.aura.signal");
    await verifyAction("dev.aura.signal", payload);
  };

  const claimAura = async (outputVct: string) => {
    if (!identity) return;
    setError("");
    setStatus("Claiming reputation proof...");
    try {
      const response = await fetch(`${services.issuerService}/v1/aura/claim`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ subjectDid: identity.did, output_vct: outputVct })
      });
      if (!response.ok) {
        throw new Error(await response.text());
      }
      const payload = await response.json();
      if (payload.credential) {
        setCredentials((prev) => [
          ...prev.filter((cred) => cred.vct !== outputVct),
          { vct: outputVct, sdJwt: payload.credential }
        ]);
      }
      setStatus("Reputation proof claimed.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Reputation claim failed");
    } finally {
      setStatus("");
    }
  };

  const loadAuraExplain = async () => {
    if (!dsrToken) {
      setError("DSR token required to fetch aura explain.");
      return;
    }
    setError("");
    setStatus("Loading reputation explanation...");
    try {
      const response = await fetch(`${services.issuerService}/v1/aura/explain`, {
        headers: { authorization: `Bearer ${dsrToken}` }
      });
      if (!response.ok) {
        throw new Error(await response.text());
      }
      setAuraExplain(JSON.stringify(await response.json(), null, 2));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Reputation explanation failed");
    } finally {
      setStatus("");
    }
  };

  const runDsrExport = async () => {
    if (!identity || !holderJwk) return;
    setError("");
    setStatus("Preparing your data export...");
    try {
      const requestResponse = await fetch(`${services.issuerService}/v1/privacy/request`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ did: identity.did })
      });
      if (!requestResponse.ok) {
        throw new Error(await requestResponse.text());
      }
      const requestPayload = await requestResponse.json();
      const kbJwt = await buildKbJwt({
        nonce: requestPayload.nonce,
        audience: requestPayload.audience,
        holderJwk,
        challengeExpiresAt: requestPayload.expires_at
      });
      const confirmResponse = await fetch(`${services.issuerService}/v1/privacy/confirm`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          requestId: requestPayload.requestId,
          nonce: requestPayload.nonce,
          kbJwt
        })
      });
      if (!confirmResponse.ok) {
        throw new Error(await confirmResponse.text());
      }
      const confirmPayload = await confirmResponse.json();
      setDsrToken(confirmPayload.dsrToken);

      const exportResponse = await fetch(`${services.issuerService}/v1/privacy/export`, {
        headers: { authorization: `Bearer ${confirmPayload.dsrToken}` }
      });
      if (!exportResponse.ok) {
        throw new Error(await exportResponse.text());
      }
      const exportPayload = await exportResponse.json();
      if (exportPayload?.nextToken) {
        setDsrToken(exportPayload.nextToken);
      }
      setDsrExport(JSON.stringify(exportPayload, null, 2));
    } catch (err) {
      setError(err instanceof Error ? err.message : "DSR export failed");
    } finally {
      setStatus("");
    }
  };

  const restrictProcessing = async () => {
    if (!dsrToken) return;
    setError("");
    setStatus("Applying restriction...");
    try {
      const response = await fetch(`${services.issuerService}/v1/privacy/restrict`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${dsrToken}`
        },
        body: JSON.stringify({ reason: "user request" })
      });
      if (!response.ok) {
        throw new Error(await response.text());
      }
      const payload = await response.json();
      if (payload?.nextToken) {
        setDsrToken(payload.nextToken);
      }
      setStatus("Processing restricted.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Restriction failed");
    } finally {
      setStatus("");
    }
  };

  const eraseUnlink = async () => {
    if (!dsrToken) return;
    setError("");
    setStatus("Unlinking off-chain data...");
    try {
      const response = await fetch(`${services.issuerService}/v1/privacy/erase`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${dsrToken}`
        },
        body: JSON.stringify({ mode: "unlink" })
      });
      if (!response.ok) {
        throw new Error(await response.text());
      }
      const payload = await response.json();
      if (payload?.nextToken) {
        setDsrToken(payload.nextToken);
      }
      setStatus("Unlink complete (off-chain data removed).");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Erase failed");
    } finally {
      setStatus("");
    }
  };

  const credentialList = useMemo(() => {
    return credentials.map((cred) => ({
      vct: cred.vct,
      disclosures: decodeDisclosureNames(cred.sdJwt)
    }));
  }, [credentials]);

  const saveServiceOverrides = () => {
    const next = {
      appGateway: serviceDraft.appGateway.trim() || defaultServiceBases().appGateway,
      didService: serviceDraft.didService.trim() || defaultServiceBases().didService,
      issuerService: serviceDraft.issuerService.trim() || defaultServiceBases().issuerService,
      verifierService: serviceDraft.verifierService.trim() || defaultServiceBases().verifierService,
      policyService: serviceDraft.policyService.trim() || defaultServiceBases().policyService
    };
    setServices(next);
    sessionStorage.setItem(storageKey, JSON.stringify(next));
    setShowServiceEditor(false);
  };

  const applyPreset = (preset: ServiceBases) => {
    setServices(preset);
    setServiceDraft(preset);
    sessionStorage.setItem(storageKey, JSON.stringify(preset));
  };

  const applyLocalPreset = () => {
    applyPreset({
      appGateway: "http://localhost:3010",
      didService: "http://localhost:3001",
      issuerService: "http://localhost:3002",
      verifierService: "http://localhost:3003",
      policyService: "http://localhost:3004"
    });
  };

  const applyOriginPreset = () => {
    const origin = window.location.origin;
    applyPreset({
      appGateway: origin,
      didService: origin,
      issuerService: origin,
      verifierService: origin,
      policyService: origin
    });
  };

  const resetServiceOverrides = () => {
    const defaults = defaultServiceBases();
    setServices(defaults);
    setServiceDraft(defaults);
    sessionStorage.removeItem(storageKey);
    setShowServiceEditor(false);
  };

  const importCredential = () => {
    setError("");
    const trimmed = importText.trim();
    if (!basicSdJwtCheck(trimmed)) {
      setError("Import failed: expected an SD-JWT VC format.");
      return;
    }
    const payload = decodeJwtPayload(trimmed.split("~")[0] ?? "");
    const derivedVct =
      typeof payload?.vct === "string" && payload.vct.length > 0 ? payload.vct : "imported.proof";
    const vct = importVct.trim() || derivedVct;
    setCredentials((prev) => [...prev.filter((cred) => cred.vct !== vct), { vct, sdJwt: trimmed }]);
    setImportText("");
    setImportVct("");
    setStatus("Imported proof stored in browser session.");
  };

  const updateChecklist = (index: number) => {
    setChecklist((prev) => {
      const next = [...prev];
      next[index] = !next[index];
      sessionStorage.setItem(checklistKey, JSON.stringify(next));
      return next;
    });
  };

  const resetChecklist = () => {
    const cleared = Array.from({ length: 10 }, () => false);
    setChecklist(cleared);
    sessionStorage.setItem(checklistKey, JSON.stringify(cleared));
  };

  return (
    <div className={`page ${theme === "night" ? "theme-night" : "theme-day"}`}>
      <div className="banner">
        <div className="row">
          <strong>Environment</strong>
          <span className="badge">browser-only</span>
          <span className="muted">
            This demo runs entirely in the browser. Keys and proofs never leave your device.
          </span>
        </div>
        <div className="muted">
          Demo assumptions: DEV_MODE=true, Hedera Testnet only, self-funded onboarding only.
        </div>
        <div className="stack">
          <div className="muted">Gateway: {services.appGateway}</div>
          <div className="muted">DID: {services.didService}</div>
          <div className="muted">Issuer: {services.issuerService}</div>
          <div className="muted">Verifier: {services.verifierService}</div>
          <div className="muted">Policy: {services.policyService}</div>
        </div>
        <div className="row">
          <button
            className="btn secondary"
            onClick={() => setTheme((prev) => (prev === "day" ? "night" : "day"))}
          >
            {theme === "day" ? "Switch to night theme" : "Switch to day theme"}
          </button>
          <button className="btn secondary" onClick={applyLocalPreset}>
            Load demo endpoints
          </button>
          <button className="btn secondary" onClick={applyOriginPreset}>
            Current origin
          </button>
          <button
            className="btn secondary"
            onClick={() => {
              setServiceDraft(services);
              setShowServiceEditor((prev) => !prev);
            }}
          >
            {showServiceEditor ? "Close editor" : "Edit endpoints"}
          </button>
          <span className="muted">Or use query params: ?gateway=http://...</span>
        </div>
        {showServiceEditor && (
          <div className="card stack">
            <label className="stack">
              <span className="muted">App gateway</span>
              <input
                value={serviceDraft.appGateway}
                onChange={(event) =>
                  setServiceDraft((prev) => ({ ...prev, appGateway: event.target.value }))
                }
              />
            </label>
            <label className="stack">
              <span className="muted">DID service</span>
              <input
                value={serviceDraft.didService}
                onChange={(event) =>
                  setServiceDraft((prev) => ({ ...prev, didService: event.target.value }))
                }
              />
            </label>
            <label className="stack">
              <span className="muted">Issuer service</span>
              <input
                value={serviceDraft.issuerService}
                onChange={(event) =>
                  setServiceDraft((prev) => ({ ...prev, issuerService: event.target.value }))
                }
              />
            </label>
            <label className="stack">
              <span className="muted">Verifier service</span>
              <input
                value={serviceDraft.verifierService}
                onChange={(event) =>
                  setServiceDraft((prev) => ({ ...prev, verifierService: event.target.value }))
                }
              />
            </label>
            <label className="stack">
              <span className="muted">Policy service</span>
              <input
                value={serviceDraft.policyService}
                onChange={(event) =>
                  setServiceDraft((prev) => ({ ...prev, policyService: event.target.value }))
                }
              />
            </label>
            <div className="row">
              <button className="btn" onClick={saveServiceOverrides}>
                Save
              </button>
              <button className="btn secondary" onClick={resetServiceOverrides}>
                Reset to localhost
              </button>
            </div>
          </div>
        )}
      </div>

      <h1>CUNCTA SSI Core Demo</h1>
      <p className="muted">
        This demo shows how a real app integrates with SSI Core. No email, no password, no
        server-stored keys.
      </p>

      {status && <div className="card">{status}</div>}
      {error && (
        <div className="card" style={{ borderColor: "#d64545", color: "#d64545" }}>
          {error}
        </div>
      )}

      <section className="card stack">
        <h2>1) Create identity</h2>
        <p className="muted">You control this identity. No email, no password.</p>
        <div className="stack">
          <div className="row">
            <label className="row checkbox">
              <input
                type="radio"
                name="onboarding-mode"
                value="user_pays"
                checked={onboardingStrategy === "user_pays"}
                onChange={() => setOnboardingStrategy("user_pays")}
                disabled={!allowUserPays}
              />
              <span>Self-funded: bring your Hedera account</span>
            </label>
          </div>
          <div className="muted">CUNCTA supports self-funded onboarding only.</div>
          {onboardingStrategy === "user_pays" && (
            <div className="card stack">
              <div className="muted">
                HashPack-first path is attempted on create. If unavailable, WalletConnect+HashPack
                is attempted next, then SDK local key entry is used.
              </div>
              {isTestnet ? (
                <label className="row checkbox">
                  <input
                    type="checkbox"
                    checked={testnetDemoOnlyConfirmed}
                    onChange={(event) => setTestnetDemoOnlyConfirmed(event.target.checked)}
                  />
                  <span>TESTNET DEMO ONLY (required to enable SDK key entry)</span>
                </label>
              ) : (
                <div className="muted">SDK key entry is disabled outside Hedera testnet.</div>
              )}
              {isTestnet && testnetDemoOnlyConfirmed && (
                <>
                  <label className="stack">
                    <span className="muted">Hedera account id (Testnet)</span>
                    <input
                      value={payerAccountId}
                      onChange={(event) => setPayerAccountId(event.target.value)}
                      placeholder="0.0.1234567"
                    />
                  </label>
                  <label className="stack">
                    <span className="muted">Hedera private key (stored in-session only)</span>
                    <input
                      type="password"
                      value={payerPrivateKey}
                      onChange={(event) => setPayerPrivateKey(event.target.value)}
                      placeholder="302e..."
                    />
                  </label>
                </>
              )}
              <div className="muted">
                Testnet only. Never paste mainnet keys. Production uses wallet connectors.
              </div>
              <div className="muted">Active onboarding method: {onboardingMethodUsed}</div>
            </div>
          )}
        </div>
        <div className="row">
          <button className="btn" onClick={createIdentity}>
            Create identity
          </button>
          {identity && <span className="badge">DID ready</span>}
        </div>
        {identity && (
          <div className="stack">
            <div>
              <strong>DID:</strong> {identity.did}
            </div>
            <div className="muted">Public key multibase: {identity.publicKeyMultibase}</div>
          </div>
        )}
      </section>

      <section className="card stack">
        <h2>2) Get a proof</h2>
        <p className="muted">
          Request a demo proof so the app can show what you are allowed to do. Stored only
          in-browser.
        </p>
        <div className="row">
          <button className="btn secondary" onClick={requestDemoCredential} disabled={!identity}>
            Request demo proof
          </button>
          <button className="btn secondary" onClick={requestSocialCredential} disabled={!identity}>
            Request social account proof
          </button>
        </div>
        <div className="stack">
          {credentialList.length === 0 && <div className="muted">No proofs stored yet.</div>}
          {credentialList.map((cred) => (
            <div key={cred.vct}>
              <strong>{cred.vct}</strong>
              <div className="muted">Disclosures: {cred.disclosures.join(", ") || "none"}</div>
            </div>
          ))}
        </div>
      </section>

      <section className="card stack">
        <h2>3) Check permission</h2>
        <p className="muted">“List item on marketplace” requires a proof of good standing.</p>
        <div className="row">
          <button
            className="btn secondary"
            onClick={() => fetchRequirements("marketplace.list_item")}
            disabled={!identity}
          >
            See what is required
          </button>
          <button
            className="btn"
            onClick={() => verifyAction("marketplace.list_item")}
            disabled={!requirements || !identity}
          >
            Check permission to list item
          </button>
        </div>
        {requirements && (
          <div className="stack">
            {requirements.requirements.map((req) => (
              <div key={req.vct}>
                <strong>{catalog[req.vct]?.display?.title ?? req.vct}</strong>
                <div className="muted">
                  Required details to share: {req.disclosures.join(", ") || "none"}
                </div>
              </div>
            ))}
          </div>
        )}
        {verificationResult && (
          <div className="stack">
            <div>
              <strong>Decision:</strong>{" "}
              {verificationResult === "ALLOW" ? "Action permitted" : "Not permitted yet"}
            </div>
            {verificationReasons.length > 0 && (
              <div className="muted">Reasons: {verificationReasons.join(", ")}</div>
            )}
          </div>
        )}
      </section>

      <section className="card stack">
        <h2>Social demo (policy-gated)</h2>
        <p className="muted">
          Every social action is ALLOW/DENY by policy verification. No passwords, DID + proofs only.
        </p>
        <div className="row">
          <button
            className="btn secondary"
            onClick={() => fetchSocialRequirements("social.profile.create")}
            disabled={!identity}
          >
            Requirements: create profile
          </button>
          <button
            className="btn secondary"
            onClick={() => fetchSocialRequirements("social.post.create")}
            disabled={!identity}
          >
            Requirements: post
          </button>
          <button
            className="btn secondary"
            onClick={() => fetchSocialRequirements("social.reply.create")}
            disabled={!identity}
          >
            Requirements: reply
          </button>
        </div>
        {socialRequirements && (
          <div className="stack">
            <div>
              <strong>Active action:</strong> {socialAction}
            </div>
            {socialRequirements.requirements.map((req) => (
              <div key={`social-${req.vct}`}>
                <strong>{catalog[req.vct]?.display?.title ?? req.vct}</strong>
                <div className="muted">
                  Required details to share: {req.disclosures.join(", ") || "none"}
                </div>
              </div>
            ))}
          </div>
        )}
        <div className="card stack">
          <strong>Trust panel</strong>
          <div>
            <strong>Required capability:</strong>{" "}
            {currentSocialRequirement?.label ?? currentSocialRequirement?.vct ?? "Not loaded"}
          </div>
          <div className="muted">
            {currentSocialRequirement
              ? (socialCapabilityDescriptions[currentSocialRequirement.vct] ??
                "Capability requirement for this action.")
              : "Load social requirements to see the current capability contract."}
          </div>
          <div>
            <strong>Aura tier:</strong> {currentAuraTier}
          </div>
          <div className="muted">
            {auraTierDescriptions[currentAuraTier] ?? auraTierDescriptions.none}
          </div>
          <div className="row">
            <button className="btn secondary" onClick={loadAuraExplain} disabled={!dsrToken}>
              Explain this tier
            </button>
            <span className="muted">
              Aura explain endpoint: <code>/v1/aura/explain</code> (requires DSR token)
            </span>
          </div>
        </div>
        <label className="stack">
          <span className="muted">Handle (hashed before storage)</span>
          <input value={socialHandle} onChange={(event) => setSocialHandle(event.target.value)} />
        </label>
        <div className="row">
          <button className="btn" onClick={createSocialProfile} disabled={!identity}>
            Create profile
          </button>
        </div>
        <label className="stack">
          <span className="muted">Post text</span>
          <textarea
            rows={3}
            value={socialPostText}
            onChange={(event) => setSocialPostText(event.target.value)}
          />
        </label>
        <div className="row">
          <button className="btn" onClick={createSocialPost} disabled={!identity}>
            Create post
          </button>
          <button className="btn secondary" onClick={createSocialReply} disabled={!identity}>
            Reply to first post
          </button>
          <button className="btn secondary" onClick={loadActiveFeed}>
            Refresh feed
          </button>
          <button className="btn secondary" onClick={loadSocialFunnel}>
            Trust funnel
          </button>
        </div>
        <div className="card stack">
          <strong>Discovery mode</strong>
          <div className="row">
            <button
              className={`btn ${feedMode === "signal" ? "" : "secondary"}`}
              onClick={() => setFeedMode("signal")}
            >
              Signal
            </button>
            <button
              className={`btn ${feedMode === "flow" ? "" : "secondary"}`}
              onClick={() => setFeedMode("flow")}
            >
              Flow
            </button>
          </div>
          {feedMode === "flow" && (
            <div className="stack">
              <label className="stack">
                <span className="muted">Trust lens</span>
                <select
                  value={flowTrustLens}
                  onChange={(event) => setFlowTrustLens(event.target.value as FlowTrustLens)}
                >
                  <option value="trusted_creator">Trusted Creator</option>
                  <option value="verified_only">Verified Only</option>
                  <option value="space_members">Space Members</option>
                </select>
              </label>
              <label className="row checkbox">
                <input
                  type="checkbox"
                  checked={flowSafetyStrict}
                  onChange={(event) => setFlowSafetyStrict(event.target.checked)}
                />
                <span>Safety strict</span>
              </label>
            </div>
          )}
        </div>
        <label className="stack">
          <span className="muted">Follow DID</span>
          <input
            value={socialFollowDid}
            onChange={(event) => setSocialFollowDid(event.target.value)}
            placeholder="did:hedera:testnet:..."
          />
        </label>
        <div className="row">
          <button className="btn secondary" onClick={createSocialFollow} disabled={!identity}>
            Follow
          </button>
        </div>
        <label className="stack">
          <span className="muted">Reply text</span>
          <textarea
            rows={2}
            value={socialReplyText}
            onChange={(event) => setSocialReplyText(event.target.value)}
          />
        </label>
        <label className="stack">
          <span className="muted">Report reason code</span>
          <input
            value={socialReportReason}
            onChange={(event) => setSocialReportReason(event.target.value)}
          />
        </label>
        <div className="row">
          <button className="btn danger" onClick={createSocialReport} disabled={!identity}>
            Report first post
          </button>
        </div>
        {socialDecision && (
          <div className="stack">
            <div>
              <strong>Policy decision:</strong> {socialDecision === "ALLOW" ? "Allowed" : "Denied"}
            </div>
            {socialReason && <div className="muted">{socialReason}</div>}
            {socialDecision !== "ALLOW" && (
              <div className="card stack">
                <strong>Why can't I post here?</strong>
                <div className="muted">
                  Missing capability:{" "}
                  {currentSocialRequirement?.label ??
                    currentSocialRequirement?.vct ??
                    "policy capability"}
                  .
                </div>
                <div className="muted">Aura tier progress: {currentAuraTier}</div>
                <div className="muted">Contributing signals: {auraSignalSummary}</div>
                <div className="muted">
                  Next step: check <code>/v1/aura/explain</code> and complete actions that increase
                  your tier.
                </div>
              </div>
            )}
          </div>
        )}
        <div className="stack">
          <strong>Feed</strong>
          {socialFeed.length === 0 && <div className="muted">No visible posts.</div>}
          {socialFeed.map((post, index) => (
            <div key={String(post.post_id ?? index)} className="card stack post-card">
              <button
                className="post-explain-icon"
                onClick={() => explainPost(String(post.post_id ?? ""))}
                disabled={!post.post_id}
                aria-label="Why shown?"
                title="Why shown?"
              >
                ?
              </button>
              <div>{String(post.content_text ?? "")}</div>
              {Array.isArray(post.trust_stamps) && post.trust_stamps.length > 0 && (
                <div className="row">
                  {(post.trust_stamps as unknown[]).map((stamp, stampIndex) => (
                    <span key={`${String(stamp)}-${stampIndex}`} className="badge badge-trust">
                      {String(stamp)}
                    </span>
                  ))}
                </div>
              )}
              <div className="muted">visibility: {String(post.visibility ?? "public")}</div>
            </div>
          ))}
        </div>
        {postExplain && (
          <div className="card stack">
            <div className="row">
              <strong>Why shown?</strong>
              <span className="muted">{postExplainId.slice(0, 12)}...</span>
              <button
                className="btn secondary"
                onClick={() => {
                  setPostExplain(null);
                  setPostExplainId("");
                }}
              >
                Close
              </button>
            </div>
            <div className="stack">
              {postExplain.reasons.map((reason) => (
                <div key={reason} className="muted">
                  {reason}
                </div>
              ))}
            </div>
            {postExplain.trustStampSummary && (
              <div className="row">
                <span className="badge badge-trust">
                  Tier: {postExplain.trustStampSummary.tier ?? "bronze"}
                </span>
                <span className="badge badge-trust">
                  Capability: {postExplain.trustStampSummary.capability ?? "can_post"}
                </span>
                <span className="badge badge-trust">
                  Domain: {postExplain.trustStampSummary.domain ?? "social"}
                </span>
              </div>
            )}
          </div>
        )}
        {socialFunnel && <pre>{socialFunnel}</pre>}
      </section>

      <section className="card stack">
        <h2>Spaces directory</h2>
        <p className="muted">
          Rules are visible before joining. Capabilities gate join, posting, and moderation.
        </p>
        <div className="row">
          <input
            value={spaceSearch}
            onChange={(event) => setSpaceSearch(event.target.value)}
            placeholder="Search spaces..."
          />
          <button className="btn secondary" onClick={loadSpaces}>
            Refresh spaces
          </button>
        </div>
        <div className="spaces-grid">
          {spaces.map((space) => (
            <button
              key={space.space_id}
              className={`card stack space-card ${selectedSpaceId === space.space_id ? "active" : ""}`}
              onClick={() => openSpace(space.space_id)}
            >
              <strong>{space.name}</strong>
              <div className="muted">/{space.slug}</div>
              <div className="muted">{space.description || "No description yet."}</div>
              <div className="row">
                <span className="badge">{space.member_count} members</span>
                <span className="badge badge-trust">
                  Posting requires: {space.posting_requirement_summary || "policy capability"}
                </span>
              </div>
            </button>
          ))}
          {spaces.length === 0 && <div className="muted">No spaces loaded yet.</div>}
        </div>
        {spaceDetail && (
          <div className="card stack">
            <div className="row">
              <h3>{spaceDetail.space.name}</h3>
              {spaceRoleBadges.map((badge) => (
                <span
                  key={badge}
                  className={`badge ${
                    badge === "Moderator"
                      ? "badge-moderator"
                      : badge === "Poster"
                        ? "badge-poster"
                        : badge === "Member"
                          ? "badge-member"
                          : "badge-trust"
                  }`}
                >
                  {badge}
                </span>
              ))}
            </div>
            <div className="muted">/{spaceDetail.space.slug}</div>
            <div className="muted">{spaceDetail.space.description}</div>
            <div className="row">
              <button
                className="btn secondary"
                onClick={() => joinSpace(spaceDetail.space.space_id)}
                disabled={!identity}
              >
                Join space
              </button>
              <button
                className="btn secondary"
                onClick={() => loadActiveSpaceFeed(spaceDetail.space.space_id)}
              >
                Refresh space feed
              </button>
              <button
                className="btn secondary"
                onClick={() => loadSpaceGovernance(spaceDetail.space.space_id)}
              >
                Governance
              </button>
              <button
                className="btn secondary"
                onClick={() => loadSpaceAnalytics(spaceDetail.space.space_id)}
              >
                Space analytics
              </button>
            </div>
            <details className="card stack" open>
              <summary>
                <strong>Presence strip</strong>
              </summary>
              <div className="row">
                <span className="badge">quiet {spacePresenceStrip?.counts?.quiet ?? 0}</span>
                <span className="badge">active {spacePresenceStrip?.counts?.active ?? 0}</span>
                <span className="badge">
                  immersive {spacePresenceStrip?.counts?.immersive ?? 0}
                </span>
                <span className="badge badge-trust">
                  you: {spacePresenceStrip?.you?.mode ?? "inactive"}
                </span>
                <button
                  className="btn secondary"
                  onClick={() => pingPresence(spaceDetail.space.space_id, "active")}
                  disabled={!identity}
                >
                  Ping active
                </button>
                <button
                  className="btn secondary"
                  onClick={() => loadPresenceStrip(spaceDetail.space.space_id)}
                >
                  Refresh
                </button>
              </div>
            </details>
            <details className="card stack" open>
              <summary>
                <strong>Hangout</strong>
              </summary>
              <div className="muted">
                Voice control-plane only (no audio stream yet). <strong>?</strong> If start/join is
                blocked, requirements or membership are missing.
              </div>
              <div className="row">
                <span className="badge">session: {spaceHuddleSessionId ? "active" : "none"}</span>
                <span className="badge">participants: {spaceHuddleParticipants}</span>
                <button
                  className="btn secondary"
                  onClick={() => createHuddleSession(spaceDetail.space.space_id)}
                  disabled={!identity}
                >
                  Start Hangout
                </button>
                <button
                  className="btn secondary"
                  onClick={() =>
                    joinHuddleSession(spaceDetail.space.space_id, spaceHuddleSessionId)
                  }
                  disabled={!identity || !spaceHuddleSessionId}
                >
                  Join Hangout
                </button>
                <button
                  className="btn secondary"
                  onClick={() => endHuddleSession(spaceDetail.space.space_id, spaceHuddleSessionId)}
                  disabled={!identity || !spaceHuddleSessionId}
                >
                  End Hangout
                </button>
              </div>
            </details>
            <details className="card stack" open>
              <summary>
                <strong>Crews</strong>
              </summary>
              <div className="muted">
                Your crew is active: {spacePresenceStrip?.crew?.active_count ?? 0}
              </div>
              <button
                className="btn secondary"
                onClick={() => loadSpaceCrews(spaceDetail.space.space_id)}
              >
                Refresh crews
              </button>
              {spaceCrews.length === 0 && <div className="muted">No crews yet.</div>}
              {spaceCrews.slice(0, 5).map((crew) => (
                <div key={crew.crew_id} className="row">
                  <span className="badge">{crew.name}</span>
                  <span className="muted">members {crew.member_count}</span>
                </div>
              ))}
            </details>
            <details className="card stack" open>
              <summary>
                <strong>Challenges</strong>
              </summary>
              <div className="muted">
                <strong>?</strong> Challenges unlock after requirements pass; only verified
                completion contributes.
              </div>
              <label className="stack">
                <span className="muted">Challenge title</span>
                <input
                  value={spaceRitualTitle}
                  onChange={(event) => setSpaceRitualTitle(event.target.value)}
                />
              </label>
              <label className="stack">
                <span className="muted">Prompt</span>
                <input
                  value={spaceRitualDescription}
                  onChange={(event) => setSpaceRitualDescription(event.target.value)}
                />
              </label>
              <div className="row">
                <button
                  className="btn secondary"
                  onClick={() => createRitual(spaceDetail.space.space_id)}
                  disabled={!identity}
                >
                  Create challenge
                </button>
                <button
                  className="btn secondary"
                  onClick={() => loadSpaceRituals(spaceDetail.space.space_id)}
                >
                  Refresh challenges
                </button>
              </div>
              {spaceRituals.length === 0 && <div className="muted">No active challenge.</div>}
              {spaceRituals.slice(0, 2).map((ritual) => (
                <div key={ritual.ritual_id} className="row">
                  <span className="badge">{ritual.title}</span>
                  <span className="muted">
                    participants {ritual.participation_count} / complete {ritual.completion_count}
                  </span>
                  <button
                    className="btn secondary"
                    onClick={() => participateRitual(spaceDetail.space.space_id, ritual.ritual_id)}
                    disabled={!identity}
                  >
                    Join
                  </button>
                  <button
                    className="btn secondary"
                    onClick={() => completeRitual(spaceDetail.space.space_id, ritual.ritual_id)}
                    disabled={!identity}
                  >
                    Complete
                  </button>
                </div>
              ))}
            </details>
            <details className="card stack" open>
              <summary>
                <strong>Top Contributors</strong>
              </summary>
              <div className="muted">
                <strong>?</strong> Ranked by verified contributions, not likes.
              </div>
              <label className="row checkbox">
                <input
                  type="checkbox"
                  checked={spaceShowOnLeaderboard}
                  onChange={(event) =>
                    updateSpaceVisibility(spaceDetail.space.space_id, event.target.checked)
                  }
                />
                <span>Show my persona in this space rankings</span>
              </label>
              <button
                className="btn secondary"
                onClick={() => loadSpaceLeaderboard(spaceDetail.space.space_id)}
              >
                Refresh rankings
              </button>
              {spaceLeaderboard.length === 0 && <div className="muted">No contributors yet.</div>}
              {spaceLeaderboard.slice(0, 8).map((entry, index) => {
                const identityBlock = (entry.identity as Record<string, unknown> | undefined) ?? {};
                const signals = (entry.signals as Record<string, unknown> | undefined) ?? {};
                return (
                  <div key={`leader-${index}`} className="row">
                    <span className="badge">#{index + 1}</span>
                    <span>
                      {String(
                        identityBlock.displayName ??
                          (identityBlock.anonymous ? "Anonymous" : "Anon")
                      )}
                    </span>
                    <span className="muted">
                      score {String(entry.score ?? 0)} | post {String(signals.post_success ?? 0)} |
                      reply {String(signals.reply_success ?? 0)} | challenge{" "}
                      {String(signals.ritual_complete ?? 0)}
                    </span>
                  </div>
                );
              })}
            </details>
            <details className="card stack" open>
              <summary>
                <strong>Top Streaks</strong>
              </summary>
              <div className="muted">
                <strong>?</strong> Streaks increment only after verified challenge completion.
              </div>
              <button
                className="btn secondary"
                onClick={() => loadSpaceTopStreaks(spaceDetail.space.space_id)}
              >
                Refresh streaks
              </button>
              {spaceTopStreaks.length === 0 && <div className="muted">No streaks yet.</div>}
              {spaceTopStreaks.slice(0, 8).map((entry, index) => (
                <div key={`streak-${index}`} className="row">
                  <span className="badge">#{index + 1}</span>
                  <span>{String(entry.streak_type ?? "challenge")}</span>
                  <span className="muted">
                    current {String(entry.current_count ?? 0)} | best{" "}
                    {String(entry.best_count ?? 0)}
                  </span>
                </div>
              ))}
            </details>
            <div className="card stack">
              <strong>Space discovery mode</strong>
              <div className="row">
                <button
                  className={`btn ${spaceFeedMode === "signal" ? "" : "secondary"}`}
                  onClick={() => setSpaceFeedMode("signal")}
                >
                  Space Signal
                </button>
                <button
                  className={`btn ${spaceFeedMode === "flow" ? "" : "secondary"}`}
                  onClick={() => setSpaceFeedMode("flow")}
                >
                  Space Flow
                </button>
              </div>
              {spaceFeedMode === "flow" && (
                <div className="stack">
                  <label className="stack">
                    <span className="muted">Space trust lens</span>
                    <select
                      value={spaceTrustLens}
                      onChange={(event) => setSpaceTrustLens(event.target.value as FlowTrustLens)}
                    >
                      <option value="trusted_creator">Trusted Creator</option>
                      <option value="verified_only">Verified Only</option>
                      <option value="space_members">Space Members</option>
                    </select>
                  </label>
                  <label className="row checkbox">
                    <input
                      type="checkbox"
                      checked={spaceSafetyStrict}
                      onChange={(event) => setSpaceSafetyStrict(event.target.checked)}
                    />
                    <span>Safety strict</span>
                  </label>
                </div>
              )}
            </div>
            <label className="stack">
              <span className="muted">Compose in space</span>
              <textarea
                rows={2}
                value={spaceComposeText}
                onChange={(event) => setSpaceComposeText(event.target.value)}
              />
            </label>
            <div className="row">
              <button
                className="btn"
                onClick={() => createSpacePost(spaceDetail.space.space_id)}
                disabled={!identity}
              >
                Post to space
              </button>
            </div>
            {spaceTrustHint && (
              <div className="card stack">
                <strong>Why can't I post here?</strong>
                <div className="muted">{spaceTrustHint}</div>
                <div className="muted">
                  Use <code>/v1/aura/explain</code> to review tier progress and contributing signals
                  summary.
                </div>
                <button className="btn secondary" onClick={loadAuraExplain} disabled={!dsrToken}>
                  Open Trust Panel
                </button>
              </div>
            )}
            <div className="stack">
              <strong>Space feed</strong>
              {spaceFeed.length === 0 && (
                <div className="muted">No visible posts for this space.</div>
              )}
              {spaceFeed.map((post, index) => (
                <div key={String(post.space_post_id ?? index)} className="card stack">
                  <div>{String(post.content_text ?? "")}</div>
                  {Array.isArray(post.trust_stamps) && post.trust_stamps.length > 0 && (
                    <div className="row">
                      {(post.trust_stamps as unknown[]).map((stamp, stampIndex) => (
                        <span key={`${String(stamp)}-${stampIndex}`} className="badge badge-trust">
                          {String(stamp)}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
            {spaceRules && (
              <div className="card stack">
                <strong>Rules & Trust</strong>
                <div className="muted">
                  Policy pack: {spaceDetail.policy_pack.display_name} (
                  {spaceDetail.policy_pack.policy_pack_id})
                </div>
                <div className="stack">
                  <strong>Join requirements</strong>
                  {spaceRules.join_requirements.map((entry) => (
                    <div key={`join-${entry.vct}`} className="row">
                      <span>{entry.label}</span>
                      <span
                        className={`badge ${hasCapability(entry.vct) ? "badge-allow" : "badge-deny"}`}
                      >
                        {hasCapability(entry.vct) ? "You have this" : "Missing"}
                      </span>
                    </div>
                  ))}
                  <strong>Post requirements</strong>
                  {spaceRules.post_requirements.map((entry) => (
                    <div key={`post-${entry.vct}`} className="row">
                      <span>{entry.label}</span>
                      <span
                        className={`badge ${hasCapability(entry.vct) ? "badge-allow" : "badge-deny"}`}
                      >
                        {hasCapability(entry.vct) ? "You have this" : "Missing"}
                      </span>
                    </div>
                  ))}
                  <strong>Moderation requirements</strong>
                  {spaceRules.moderation_requirements.map((entry) => (
                    <div key={`mod-${entry.vct}`} className="row">
                      <span>{entry.label}</span>
                      <span
                        className={`badge ${hasCapability(entry.vct) ? "badge-allow" : "badge-deny"}`}
                      >
                        {hasCapability(entry.vct) ? "You have this" : "Missing"}
                      </span>
                    </div>
                  ))}
                </div>
                <div className="muted">
                  Why? Open Trust Panel for aura and capability explainers.
                </div>
              </div>
            )}
            {spaceGovernance && (
              <div className="card stack">
                <strong>Governance transparency</strong>
                <div className="muted">
                  Pack: {spaceGovernance.policy_pack?.display_name ?? "n/a"} (
                  {spaceGovernance.policy_pack?.policy_pack_id ?? "n/a"})
                </div>
                <div className="row">
                  <span className="badge badge-trust">
                    Post floor: {spaceGovernance.trust_floor?.post ?? "bronze"}
                  </span>
                  <span className="badge">
                    Post policy v{spaceGovernance.policy_versions?.post?.version ?? "?"}
                  </span>
                  <span className="badge">
                    Pinning: {spaceGovernance.pinning?.post ? "pinned" : "not pinned"}
                  </span>
                </div>
              </div>
            )}
            {canModerateInSpace && (
              <div className="card stack">
                <div className="row">
                  <strong>Moderation queue (stub)</strong>
                  <button
                    className="btn secondary"
                    onClick={() => loadModerationCases(spaceDetail.space.space_id)}
                    disabled={!identity}
                  >
                    Refresh cases
                  </button>
                  <button
                    className="btn secondary"
                    onClick={() => loadSpaceModerationAudit(spaceDetail.space.space_id)}
                    disabled={!identity}
                  >
                    Audit view
                  </button>
                </div>
                {moderationCases.length === 0 && (
                  <div className="muted">No open moderation cases.</div>
                )}
                {moderationCases.map((entry) => (
                  <div key={entry.case_id} className="row">
                    <span className="badge">{entry.status}</span>
                    <span className="muted">Report: {entry.report_id.slice(0, 12)}...</span>
                    {entry.status !== "RESOLVED" && (
                      <button
                        className="btn secondary"
                        onClick={() =>
                          resolveModerationCase(spaceDetail.space.space_id, entry.case_id)
                        }
                        disabled={!identity}
                      >
                        Resolve
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
            {spaceModerationAudit.length > 0 && (
              <div className="card stack">
                <strong>Moderator audit (hash-only)</strong>
                {spaceModerationAudit.slice(0, 6).map((entry, idx) => (
                  <div key={`${String(entry.audit_hash ?? idx)}`} className="row">
                    <span className="badge">{String(entry.operation ?? "op")}</span>
                    <span className="muted">
                      audit: {String(entry.audit_hash ?? "").slice(0, 16)}...
                    </span>
                    <span className="muted">reason: {String(entry.reason_code ?? "n/a")}</span>
                  </div>
                ))}
              </div>
            )}
            {spaceAnalytics && (
              <div className="card stack">
                <strong>Space analytics</strong>
                <pre>{spaceAnalytics}</pre>
              </div>
            )}
          </div>
        )}
      </section>

      <section className="card stack">
        <h2>4) Reputation (derived from actions)</h2>
        <p className="muted">
          Reputation here is domain-scoped and derived from verifiable actions, not social graphs.
          This step uses a DEV_MODE-only action.
        </p>
        <div className="row">
          <button className="btn secondary" onClick={simulateAura} disabled={!identity}>
            Simulate successful listing
          </button>
          <button className="btn secondary" onClick={loadAuraExplain} disabled={!dsrToken}>
            View reputation explanation (needs DSR token)
          </button>
        </div>
        <div className="row">
          <button
            className="btn"
            onClick={() => claimAura("cuncta.marketplace.seller_good_standing")}
            disabled={!identity}
          >
            Claim seller good standing
          </button>
          <button
            className="btn"
            onClick={() => claimAura("cuncta.marketplace.trusted_seller_tier")}
            disabled={!identity}
          >
            Claim trusted seller tier
          </button>
        </div>
        {auraExplain && <pre>{auraExplain}</pre>}
      </section>

      <section className="card stack">
        <h2>Privacy panel</h2>
        <p className="muted">
          Export returns hash-only records. Unlink removes off-chain data; on-chain anchors remain
          immutable.
        </p>
        <div className="row">
          <button className="btn secondary" onClick={runDsrExport} disabled={!identity}>
            Request data export
          </button>
          <button className="btn secondary" onClick={restrictProcessing} disabled={!dsrToken}>
            Restrict processing
          </button>
          <button className="btn danger" onClick={eraseUnlink} disabled={!dsrToken}>
            Erase / unlink
          </button>
        </div>
        {dsrToken && (
          <div className="muted">DSR token (short-lived): {dsrToken.slice(0, 10)}...</div>
        )}
        {dsrExport && <pre>{dsrExport}</pre>}
      </section>

      <section className="card stack">
        <div className="row">
          <h2>Developer tools</h2>
          <button className="btn secondary" onClick={() => setShowAdvanced((prev) => !prev)}>
            {showAdvanced ? "Hide" : "Show"}
          </button>
        </div>
        <p className="muted">
          Optional tools for demos. Imported proofs stay in memory and are never sent unless used in
          a permission check.
        </p>
        {showAdvanced && (
          <div className="stack">
            <label className="stack">
              <span className="muted">Proof type (optional)</span>
              <input
                value={importVct}
                onChange={(event) => setImportVct(event.target.value)}
                placeholder="cuncta.marketplace.seller_good_standing"
              />
            </label>
            <label className="stack">
              <span className="muted">Paste SD-JWT VC</span>
              <textarea
                rows={4}
                value={importText}
                onChange={(event) => setImportText(event.target.value)}
                placeholder="Paste the SD-JWT VC here"
              />
            </label>
            <div className="row">
              <button className="btn" onClick={importCredential}>
                Import proof
              </button>
              <span className="muted">Format check only. No validation performed.</span>
            </div>
          </div>
        )}
      </section>

      <section className="card stack">
        <h2>What happens behind the scenes</h2>
        <ul className="muted">
          <li>Keys stay in your browser. No private keys leave this page.</li>
          <li>All proofs are signed client-side and bound to nonce + audience.</li>
          <li>Server storage is hash-only (no raw tokens, claims, or presentations).</li>
        </ul>
      </section>

      <aside className="card stack checklist">
        <div className="row">
          <h2>Demo checklist</h2>
          <button className="btn secondary" onClick={() => setShowChecklist((prev) => !prev)}>
            {showChecklist ? "Collapse" : "Expand"}
          </button>
          <button className="btn secondary" onClick={resetChecklist}>
            Reset checklist
          </button>
        </div>
        {showChecklist && (
          <div className="stack">
            {[
              "Create identity",
              "Check permission (expect DENY first)",
              "Issue or import proof",
              "Check permission (expect ALLOW)",
              "Simulate reputation signal (DEV_MODE)",
              "Claim capability (if queued)",
              "View reputation explanation",
              "Export your data",
              "Restrict processing",
              "Erase/unlink"
            ].map((label, index) => (
              <label key={label} className="row checkbox">
                <input
                  type="checkbox"
                  checked={checklist[index]}
                  onChange={() => updateChecklist(index)}
                />
                <span>{label}</span>
              </label>
            ))}
          </div>
        )}
      </aside>

      <button
        className={`command-orb ${hasPulseCards ? "has-pulse" : ""}`}
        aria-label="Open command launcher"
        onClick={() => setShowCommandOrb((prev) => !prev)}
      >
        Orb
      </button>
      {showCommandOrb && (
        <div className="command-orb-panel card stack">
          <strong>Command Orb</strong>
          <label className="stack">
            <span className="muted">Intent</span>
            <input
              value={commandIntent}
              onChange={(event) => setCommandIntent(event.target.value)}
              placeholder="join hangout"
            />
          </label>
          <button className="btn secondary" onClick={runCommandPlan}>
            Generate quick actions
          </button>
          {commandPlan && (
            <div className="card stack">
              <div className="row">
                <strong>Quick Actions</strong>
                <span className="badge">{commandPlan.ready_state}</span>
                <button
                  className="post-explain-icon"
                  aria-label="Why denied"
                  title={commandPlan.deny_reason ?? "No denial reason"}
                >
                  ?
                </button>
              </div>
              {commandPlan.action_plan.map((entry, index) => (
                <div key={`${entry.action_id}-${index}`} className="row">
                  <span className="badge">{entry.action_id}</span>
                  <span className="muted">{entry.intent}</span>
                </div>
              ))}
              {commandPlan.required_capabilities.length > 0 && (
                <div className="stack">
                  <strong>Required capabilities</strong>
                  {commandPlan.required_capabilities.map((entry) => (
                    <span key={entry.vct} className="muted">
                      {entry.label ?? entry.vct}
                    </span>
                  ))}
                </div>
              )}
              {commandPlan.next_best_actions.length > 0 && (
                <div className="stack">
                  <strong>Next best actions</strong>
                  {commandPlan.next_best_actions.map((entry) => (
                    <span key={entry} className="muted">
                      {entry}
                    </span>
                  ))}
                </div>
              )}
              <div className="stack">
                <strong>Cost & Payment (Advisory)</strong>
                {Array.isArray(commandPlan.feeQuote?.items) &&
                commandPlan.feeQuote.items.length > 0 ? (
                  <div className="stack">
                    <span className="muted">Fee quote</span>
                    {commandPlan.feeQuote.items.map((item, index) => (
                      <span
                        key={`${item.asset?.kind ?? "asset"}-${item.asset?.tokenId ?? "native"}-${index}`}
                        className="muted"
                      >
                        {(item.asset?.kind ?? "ASSET").toUpperCase()}
                        {item.asset?.kind === "HTS" && item.asset?.tokenId
                          ? ` (${item.asset.tokenId})`
                          : ""}
                        {" · "}
                        {item.amount ?? "0"}
                        {item.purpose ? ` · ${item.purpose}` : ""}
                      </span>
                    ))}
                  </div>
                ) : (
                  <span className="muted">No fee quote provided.</span>
                )}
                {Array.isArray(commandPlan.paymentRequest?.instructions) &&
                commandPlan.paymentRequest.instructions.length > 0 ? (
                  <div className="stack">
                    <span className="muted">Payment instructions</span>
                    {commandPlan.paymentRequest.instructions.map((instruction, index) => (
                      <span
                        key={`${instruction.to?.accountId ?? "receiver"}-${instruction.asset?.tokenId ?? "native"}-${index}`}
                        className="muted"
                      >
                        to {instruction.to?.accountId ?? "unknown"}
                        {" · "}
                        {(instruction.asset?.kind ?? "ASSET").toUpperCase()}
                        {instruction.asset?.kind === "HTS" && instruction.asset?.tokenId
                          ? ` (${instruction.asset.tokenId})`
                          : ""}
                        {" · "}
                        {instruction.amount ?? "0"}
                        {instruction.memo ? ` · memo: ${instruction.memo}` : ""}
                      </span>
                    ))}
                  </div>
                ) : (
                  <span className="muted">
                    Payment instructions unavailable (receiver not configured).
                  </span>
                )}
                <details>
                  <summary className="muted">Fingerprint details</summary>
                  <div className="stack">
                    <span className="muted">
                      feeScheduleFingerprint: {commandPlan.feeScheduleFingerprint ?? "not provided"}
                    </span>
                    <span className="muted">
                      feeQuoteFingerprint: {commandPlan.feeQuoteFingerprint ?? "not provided"}
                    </span>
                    <span className="muted">
                      paymentRequestFingerprint:{" "}
                      {commandPlan.paymentRequestFingerprint ?? "not provided"}
                    </span>
                    <span className="muted">
                      paymentsConfigFingerprint:{" "}
                      {commandPlan.paymentsConfigFingerprint ?? "not provided"}
                    </span>
                  </div>
                </details>
              </div>
            </div>
          )}
          <button className="btn secondary" onClick={createIdentity}>
            Create identity
          </button>
          <button className="btn secondary" onClick={requestSocialCredential} disabled={!identity}>
            Request social proof
          </button>
          <button className="btn secondary" onClick={createSocialPost} disabled={!identity}>
            Compose and post
          </button>
          <button className="btn secondary" onClick={loadSocialFeed}>
            Open feed
          </button>
          <button className="btn secondary" onClick={loadSpaces}>
            Spaces
          </button>
          <button
            className="btn secondary"
            onClick={async () => {
              if (!selectedSpaceId) return;
              await Promise.all([
                loadPulse(selectedSpaceId),
                loadPulsePreferences(selectedSpaceId)
              ]);
              setShowPulsePanel((prev) => !prev);
            }}
            disabled={!selectedSpaceId}
          >
            Pulse
          </button>
          <button className="btn secondary" onClick={runDsrExport} disabled={!identity}>
            Open privacy panel actions
          </button>
          <div className="card stack">
            <strong>Entertainment</strong>
            <label className="stack">
              <span className="muted">Space id (for scoped actions)</span>
              <input
                value={entSpaceId}
                onChange={(event) => setEntSpaceId(event.target.value)}
                placeholder="space uuid"
              />
            </label>
            <div className="row">
              <button
                className="btn secondary"
                onClick={() =>
                  runEntertainmentAction(
                    "media.emoji.pack.create",
                    "/v1/social/media/emoji/pack/create",
                    {
                      spaceId: entSpaceId || undefined,
                      visibility: "private"
                    }
                  ).then((payload) => {
                    if (payload?.packId) setEntEmojiPackId(String(payload.packId));
                  })
                }
                disabled={!identity}
              >
                Emoji Studio: create pack
              </button>
              <button
                className="post-explain-icon"
                aria-label="Explain emoji pack create gate"
                title="Explain"
                onClick={() =>
                  explainCapability("media.emoji.pack.create", entSpaceId || undefined)
                }
              >
                ?
              </button>
            </div>
            <div className="row">
              <button
                className="btn secondary"
                onClick={() =>
                  runEntertainmentAction(
                    "media.emoji.pack.publish",
                    "/v1/social/media/emoji/pack/publish",
                    {
                      packId: entEmojiPackId,
                      spaceId: entSpaceId
                    },
                    { spaceId: entSpaceId }
                  )
                }
                disabled={!identity || !entEmojiPackId || !entSpaceId}
              >
                Emoji Studio: publish to space
              </button>
              <button
                className="post-explain-icon"
                aria-label="Explain emoji publish gate"
                title="Explain"
                onClick={() =>
                  explainCapability("media.emoji.pack.publish", entSpaceId || undefined)
                }
              >
                ?
              </button>
            </div>
            <div className="row">
              <button
                className="btn secondary"
                onClick={() =>
                  runEntertainmentAction(
                    "media.soundpack.create",
                    "/v1/social/media/soundpack/create",
                    {
                      spaceId: entSpaceId || undefined,
                      visibility: "private"
                    }
                  ).then((payload) => {
                    if (payload?.packId) setEntSoundpackId(String(payload.packId));
                  })
                }
                disabled={!identity}
              >
                Soundpacks: create pack
              </button>
              <button
                className="btn secondary"
                onClick={() =>
                  runEntertainmentAction(
                    "media.soundpack.activate_in_space",
                    "/v1/social/media/soundpack/activate",
                    { packId: entSoundpackId, spaceId: entSpaceId },
                    { spaceId: entSpaceId }
                  )
                }
                disabled={!identity || !entSoundpackId || !entSpaceId}
              >
                Soundpacks: activate in space
              </button>
            </div>
            <div className="row">
              <button
                className="btn secondary"
                onClick={() =>
                  runEntertainmentAction(
                    "presence.set_mode",
                    "/v1/social/presence/set_mode",
                    { spaceId: entSpaceId, mode: "quiet" },
                    { spaceId: entSpaceId }
                  )
                }
                disabled={!identity || !entSpaceId}
              >
                Presence: set quiet
              </button>
              <button
                className="btn secondary"
                onClick={() => {
                  if (!entSpaceId) return;
                  loadPresenceState(entSpaceId);
                }}
                disabled={!entSpaceId}
              >
                Presence: view state
              </button>
            </div>
            <div className="row">
              <button
                className="btn secondary"
                onClick={() =>
                  runEntertainmentAction(
                    "sync.hangout.create_session",
                    "/v1/social/sync/hangout/create_session",
                    { spaceId: entSpaceId },
                    { spaceId: entSpaceId }
                  ).then((payload) => {
                    if (payload?.sessionId) setSpaceHuddleSessionId(String(payload.sessionId));
                    if (payload?.participant_count) {
                      setSpaceHuddleParticipants(Number(payload.participant_count));
                    }
                  })
                }
                disabled={!identity || !entSpaceId}
              >
                Hangout: start
              </button>
              <button
                className="btn secondary"
                onClick={() =>
                  runEntertainmentAction(
                    "sync.hangout.join_session",
                    "/v1/social/sync/hangout/join_session",
                    { sessionId: spaceHuddleSessionId, spaceId: entSpaceId },
                    { spaceId: entSpaceId }
                  ).then((payload) => {
                    if (payload?.participant_count) {
                      setSpaceHuddleParticipants(Number(payload.participant_count));
                    }
                  })
                }
                disabled={!identity || !entSpaceId || !spaceHuddleSessionId}
              >
                Hangout: join
              </button>
              <button
                className="btn secondary"
                onClick={() =>
                  runEntertainmentAction(
                    "sync.hangout.end_session",
                    "/v1/social/sync/hangout/end_session",
                    {
                      sessionId: spaceHuddleSessionId,
                      spaceId: entSpaceId,
                      reasonCode: "manual_end"
                    },
                    { spaceId: entSpaceId }
                  ).then(() => {
                    setSpaceHuddleSessionId("");
                    setSpaceHuddleParticipants(0);
                  })
                }
                disabled={!identity || !entSpaceId || !spaceHuddleSessionId}
              >
                Hangout: end
              </button>
            </div>
            <div className="row">
              <button
                className="btn secondary"
                onClick={() =>
                  runEntertainmentAction(
                    "ritual.create",
                    "/v1/social/ritual/create",
                    {
                      spaceId: entSpaceId,
                      title: "10-minute drop",
                      description: "Drop in now",
                      durationMinutes: 10
                    },
                    { spaceId: entSpaceId }
                  ).then(() => loadSpaceRituals(entSpaceId))
                }
                disabled={!identity || !entSpaceId}
              >
                Challenge: create
              </button>
              <button
                className="btn secondary"
                onClick={() => {
                  if (!entSpaceId) return;
                  loadSpaceLeaderboard(entSpaceId);
                }}
                disabled={!entSpaceId}
              >
                Rankings: refresh
              </button>
            </div>
            <div className="row">
              <button
                className="btn secondary"
                onClick={() =>
                  runEntertainmentAction(
                    "sync.scroll.create_session",
                    "/v1/social/sync/scroll/create_session",
                    { spaceId: entSpaceId },
                    { spaceId: entSpaceId }
                  ).then((payload) => {
                    if (payload?.sessionId) setEntScrollSessionId(String(payload.sessionId));
                  })
                }
                disabled={!identity || !entSpaceId}
              >
                Start Scroll Group
              </button>
              <button
                className="post-explain-icon"
                aria-label="Explain scroll host gate"
                title="Explain"
                onClick={() =>
                  explainCapability("sync.scroll.create_session", entSpaceId || undefined)
                }
              >
                ?
              </button>
              <button
                className="btn secondary"
                onClick={() =>
                  runEntertainmentAction(
                    "sync.scroll.join_session",
                    "/v1/social/sync/scroll/join_session",
                    { sessionId: entScrollSessionId, spaceId: entSpaceId },
                    { spaceId: entSpaceId }
                  ).then((payload) => {
                    const token = String(payload?.permissionToken ?? "");
                    if (!token || !entScrollSessionId) return;
                    setEntScrollPermissionToken(token);
                    subscribeScrollStream(entScrollSessionId, token);
                  })
                }
                disabled={!identity || !entScrollSessionId || !entSpaceId}
              >
                Join Scroll Group
              </button>
              <button
                className="btn secondary"
                onClick={() =>
                  runEntertainmentAction(
                    "sync.scroll.end_session",
                    "/v1/social/sync/scroll/end_session",
                    { sessionId: entScrollSessionId, spaceId: entSpaceId },
                    { spaceId: entSpaceId }
                  )
                }
                disabled={!identity || !entScrollSessionId || !entSpaceId}
              >
                End Scroll Group
              </button>
            </div>
            <div className="row">
              <button
                className="btn secondary"
                onClick={() =>
                  runEntertainmentAction(
                    "sync.scroll.sync_event",
                    "/v1/social/sync/scroll/sync_event",
                    {
                      sessionId: entScrollSessionId,
                      permissionToken: entScrollPermissionToken,
                      eventType: "SCROLL_SYNC",
                      payload: { scrollY: Math.round(window.scrollY), t: Date.now() }
                    },
                    { spaceId: entSpaceId }
                  )
                }
                disabled={!identity || !entScrollSessionId || !entScrollPermissionToken}
              >
                Send Scroll Sync
              </button>
              <label className="muted">
                <input
                  type="checkbox"
                  checked={followHostScroll}
                  onChange={(event) => setFollowHostScroll(event.target.checked)}
                />{" "}
                follow host
              </label>
            </div>
            <div className="row">
              <button
                className="btn secondary"
                onClick={() =>
                  runEntertainmentAction(
                    "sync.listen.create_session",
                    "/v1/social/sync/listen/create_session",
                    { spaceId: entSpaceId },
                    { spaceId: entSpaceId }
                  ).then((payload) => {
                    if (payload?.sessionId) setEntListenSessionId(String(payload.sessionId));
                  })
                }
                disabled={!identity || !entSpaceId}
              >
                Start Listen Group
              </button>
              <button
                className="post-explain-icon"
                aria-label="Explain listen host gate"
                title="Explain"
                onClick={() =>
                  explainCapability("sync.listen.create_session", entSpaceId || undefined)
                }
              >
                ?
              </button>
              <button
                className="btn secondary"
                onClick={() =>
                  runEntertainmentAction(
                    "sync.listen.join_session",
                    "/v1/social/sync/listen/join_session",
                    { sessionId: entListenSessionId, spaceId: entSpaceId },
                    { spaceId: entSpaceId }
                  ).then((payload) => {
                    const token = String(payload?.permissionToken ?? "");
                    if (!token || !entListenSessionId) return;
                    setEntListenPermissionToken(token);
                    subscribeListenStream(entListenSessionId, token);
                  })
                }
                disabled={!identity || !entListenSessionId || !entSpaceId}
              >
                Join Listen Group
              </button>
              <button
                className="btn secondary"
                onClick={() =>
                  runEntertainmentAction(
                    "sync.listen.end_session",
                    "/v1/social/sync/listen/end_session",
                    { sessionId: entListenSessionId, spaceId: entSpaceId },
                    { spaceId: entSpaceId }
                  )
                }
                disabled={!identity || !entListenSessionId || !entSpaceId}
              >
                End Listen Group
              </button>
            </div>
            <div className="row">
              <button
                className="btn secondary"
                onClick={() =>
                  runEntertainmentAction(
                    "sync.listen.broadcast_control",
                    "/v1/social/sync/listen/broadcast_control",
                    {
                      sessionId: entListenSessionId,
                      permissionToken: entListenPermissionToken,
                      eventType: "LISTEN_STATE",
                      payload: {
                        playing: true,
                        cursorMs: Math.floor(Date.now() % 240000),
                        trackId: "placeholder-track"
                      }
                    },
                    { spaceId: entSpaceId }
                  )
                }
                disabled={!identity || !entListenSessionId || !entListenPermissionToken}
              >
                Broadcast Listen State
              </button>
            </div>
            {showCapabilityExplain && <div className="muted">{showCapabilityExplain}</div>}
            {syncHint && <div className="muted">{syncHint}</div>}
            {listenState && <pre>{listenState}</pre>}
            {presenceState && <pre>{presenceState}</pre>}
          </div>
        </div>
      )}
      {showPulsePanel && selectedSpaceId && (
        <div className="pulse-panel card stack">
          <div className="row">
            <strong>Pulse</strong>
            <button className="btn secondary" onClick={() => setShowPulsePanel(false)}>
              Close
            </button>
          </div>
          {pulsePreferences && (
            <div className="row">
              <label className="row checkbox">
                <input
                  type="checkbox"
                  checked={pulsePreferences.enabled}
                  onChange={(event) =>
                    updatePulsePreference(selectedSpaceId, { enabled: event.target.checked })
                  }
                />
                <span>Pulse enabled</span>
              </label>
              <label className="row checkbox">
                <input
                  type="checkbox"
                  checked={pulsePreferences.notifyCrews}
                  onChange={(event) =>
                    updatePulsePreference(selectedSpaceId, { notifyCrews: event.target.checked })
                  }
                />
                <span>Crews</span>
              </label>
              <label className="row checkbox">
                <input
                  type="checkbox"
                  checked={pulsePreferences.notifyHangouts}
                  onChange={(event) =>
                    updatePulsePreference(selectedSpaceId, { notifyHangouts: event.target.checked })
                  }
                />
                <span>Hangouts</span>
              </label>
              <label className="row checkbox">
                <input
                  type="checkbox"
                  checked={pulsePreferences.notifyChallenges}
                  onChange={(event) =>
                    updatePulsePreference(selectedSpaceId, {
                      notifyChallenges: event.target.checked
                    })
                  }
                />
                <span>Challenges</span>
              </label>
              <label className="row checkbox">
                <input
                  type="checkbox"
                  checked={pulsePreferences.notifyStreaks}
                  onChange={(event) =>
                    updatePulsePreference(selectedSpaceId, { notifyStreaks: event.target.checked })
                  }
                />
                <span>Streaks</span>
              </label>
              <label className="row checkbox">
                <input
                  type="checkbox"
                  checked={pulsePreferences.notifyRankings}
                  onChange={(event) =>
                    updatePulsePreference(selectedSpaceId, {
                      notifyRankings: event.target.checked
                    })
                  }
                />
                <span>Rankings</span>
              </label>
            </div>
          )}
          {(pulseSummary?.cards?.length ?? 0) === 0 && (
            <div className="muted">No pulse cards right now for this space.</div>
          )}
          {(pulseSummary?.cards ?? []).map((card) => (
            <div key={card.type} className="pulse-card">
              <div className="row">
                <strong>{card.title}</strong>
                <button
                  className="post-explain-icon pulse-explain-icon"
                  aria-label={`Explain ${card.type}`}
                  title="Explain"
                  onClick={() => togglePulseExplain(card.type)}
                >
                  ?
                </button>
              </div>
              <div className="muted">{String(card.value)}</div>
              {pulseExplainOpen[card.type] && <div className="muted">{card.explain}</div>}
              <button
                className="btn secondary"
                onClick={() => runPulseCta(selectedSpaceId, card)}
                disabled={!selectedSpaceId}
              >
                {card.cta}
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
