import { useMemo, useState } from "react";
import { SignJWT, importJWK } from "jose";
import * as Registrar from "@hiero-did-sdk/registrar";
import type { OnboardingStrategy } from "@cuncta/shared";
import { fromBase64Url, toBase64Url } from "./lib/encoding";
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
    disclosures: string[];
    predicates?: Array<{ path: string; op: string; value?: unknown }>;
  }>;
  obligations?: Array<{ type: string }>;
  binding?: { mode: string; require: boolean };
  challenge: { nonce: string; audience: string; expires_at: string };
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
    .filter((entry): entry is OnboardingStrategy => entry === "sponsored" || entry === "user_pays");
};

const allowedOnboardingStrategies = parseOnboardingStrategyList(
  import.meta.env.VITE_ONBOARDING_STRATEGY_ALLOWED
);
const hederaNetwork = import.meta.env.VITE_HEDERA_NETWORK ?? "testnet";
const isTestnet = hederaNetwork === "testnet";
const defaultOnboardingStrategy: OnboardingStrategy =
  import.meta.env.VITE_ONBOARDING_STRATEGY_DEFAULT === "user_pays" ? "user_pays" : "sponsored";
const initialOnboardingStrategy =
  allowedOnboardingStrategies.length > 0 &&
  !allowedOnboardingStrategies.includes(defaultOnboardingStrategy)
    ? allowedOnboardingStrategies[0]!
    : defaultOnboardingStrategy;

const DEVICE_ID_STORAGE_KEY = "cuncta_device_id";

const getDeviceId = () => {
  const existing = window.localStorage.getItem(DEVICE_ID_STORAGE_KEY);
  if (existing) return existing;
  const generated =
    window.crypto?.randomUUID?.() ?? `dev-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  window.localStorage.setItem(DEVICE_ID_STORAGE_KEY, generated);
  return generated;
};

const withDeviceHeaders = (headers?: Record<string, string>) => ({
  ...(headers ?? {}),
  "x-device-id": getDeviceId()
});

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
  const [payerAccountId, setPayerAccountId] = useState("");
  const [payerPrivateKey, setPayerPrivateKey] = useState("");
  const [useOperatorFallback, setUseOperatorFallback] = useState(false);
  const [sponsoredDisabled, setSponsoredDisabled] = useState(false);
  const [auraExplain, setAuraExplain] = useState<string>("");
  const [dsrToken, setDsrToken] = useState<string>("");
  const [dsrExport, setDsrExport] = useState<string>("");
  const [status, setStatus] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [importText, setImportText] = useState("");
  const [importVct, setImportVct] = useState("");
  const [showChecklist, setShowChecklist] = useState(true);
  const [checklist, setChecklist] = useState<boolean[]>(() => loadChecklist());

  const holderJwk = useMemo(() => {
    if (!identity) return null;
    return buildHolderJwk(identity.privateKey, identity.publicKey);
  }, [identity]);

  const allowSponsored =
    allowedOnboardingStrategies.length === 0 || allowedOnboardingStrategies.includes("sponsored");
  const allowUserPays =
    allowedOnboardingStrategies.length === 0 || allowedOnboardingStrategies.includes("user_pays");

  const createIdentity = async () => {
    setError("");
    setStatus("Creating identity...");
    setSponsoredDisabled(false);
    try {
      const keypair = await generateKeypair();
      const publicKeyMultibase = toBase58Multibase(keypair.publicKey);
      if (!publicKeyMultibase.startsWith("z")) {
        throw new Error("publicKeyMultibase must start with 'z'.");
      }

      let did: string | null = null;
      if (onboardingStrategy === "sponsored") {
        const requestResponse = await fetch(
          `${services.appGateway}/v1/onboard/did/create/request`,
          {
            method: "POST",
            headers: withDeviceHeaders({ "content-type": "application/json" }),
            body: JSON.stringify({
              network: "testnet",
              publicKeyMultibase,
              options: { topicManagement: "shared", includeServiceEndpoints: true }
            })
          }
        );
        if (!requestResponse.ok) {
          const bodyText = await requestResponse.text();
          let payload: { error?: string; message?: string } | null = null;
          try {
            payload = JSON.parse(bodyText) as { error?: string; message?: string };
          } catch {
            payload = null;
          }
          if (
            requestResponse.status === 403 &&
            payload?.error === "sponsored_onboarding_disabled"
          ) {
            setSponsoredDisabled(true);
            setOnboardingStrategy("user_pays");
            throw new Error("Sponsored onboarding disabled. Switch to self-funded.");
          }
          throw new Error(payload?.message ?? bodyText);
        }
        const requestPayload = await requestResponse.json();
        const payloadToSign = fromBase64Url(requestPayload.signingRequest.payloadToSignB64u);
        const signature = await signPayload(payloadToSign, keypair.privateKey);
        const submitResponse = await fetch(`${services.appGateway}/v1/onboard/did/create/submit`, {
          method: "POST",
          headers: withDeviceHeaders({ "content-type": "application/json" }),
          body: JSON.stringify({
            state: requestPayload.state,
            signatureB64u: toBase64Url(signature),
            waitForVisibility: false
          })
        });
        if (!submitResponse.ok) {
          throw new Error(await submitResponse.text());
        }
        const submitPayload = await submitResponse.json();
        did = submitPayload.did;
      } else {
        const payerId = payerAccountId.trim();
        const payerKey = payerPrivateKey.trim();
        let effectivePayerId = payerId;
        let effectivePayerKey = payerKey;
        if (!effectivePayerId || !effectivePayerKey) {
          if (!isTestnet) {
            throw new Error("Self-funded onboarding requires payer credentials.");
          }
          if (!useOperatorFallback) {
            throw new Error("Payer credentials required or enable testnet demo fallback.");
          }
          const operatorId = import.meta.env.VITE_HEDERA_OPERATOR_ID;
          const operatorKey = import.meta.env.VITE_HEDERA_OPERATOR_PRIVATE_KEY;
          if (!operatorId || !operatorKey) {
            throw new Error("Missing VITE_HEDERA_OPERATOR_* for testnet fallback.");
          }
          effectivePayerId = operatorId;
          effectivePayerKey = operatorKey;
        }
        if (!effectivePayerId || !effectivePayerKey) {
          throw new Error("Payer account id + private key required for self-funded onboarding.");
        }
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
      const response = await fetch(`${services.appGateway}/v1/onboard/issue`, {
        method: "POST",
        headers: withDeviceHeaders({ "content-type": "application/json" }),
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
    <div className="page">
      <div className="banner">
        <div className="row">
          <strong>Environment</strong>
          <span className="badge">browser-only</span>
          <span className="muted">
            This demo runs entirely in the browser. Keys and proofs never leave your device.
          </span>
        </div>
        <div className="muted">
          Demo assumptions: DEV_MODE=true, onboarding strategy selectable (sponsored or
          self-funded).
        </div>
        <div className="stack">
          <div className="muted">Gateway: {services.appGateway}</div>
          <div className="muted">DID: {services.didService}</div>
          <div className="muted">Issuer: {services.issuerService}</div>
          <div className="muted">Verifier: {services.verifierService}</div>
          <div className="muted">Policy: {services.policyService}</div>
        </div>
        <div className="row">
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
                value="sponsored"
                checked={onboardingStrategy === "sponsored"}
                onChange={() => setOnboardingStrategy("sponsored")}
                disabled={!allowSponsored}
              />
              <span>Sponsored: no wallet required</span>
            </label>
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
          {sponsoredDisabled && (
            <div className="muted">Sponsored onboarding is disabled. Self-funded is required.</div>
          )}
          {onboardingStrategy === "user_pays" && (
            <div className="card stack">
              <div className="muted">
                Demo warning: never paste real mainnet keys here. Use a wallet connector in
                production.
              </div>
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
              {isTestnet && !payerAccountId.trim() && !payerPrivateKey.trim() && (
                <label className="row checkbox">
                  <input
                    type="checkbox"
                    checked={useOperatorFallback}
                    onChange={(event) => setUseOperatorFallback(event.target.checked)}
                  />
                  <span>Use local testnet operator account for demo</span>
                </label>
              )}
              {!isTestnet && (
                <div className="muted">Testnet-only shortcut disabled on non-testnet networks.</div>
              )}
              <div className="muted">
                Never use mainnet keys here. Production uses wallet connectors.
              </div>
              <div className="muted">Connect wallet later (WalletConnect not wired yet).</div>
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
        <h2>5) Your data choices</h2>
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
    </div>
  );
}
