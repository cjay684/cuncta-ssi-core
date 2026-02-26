import path from "node:path";
import { readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { CompactSign, compactVerify, importJWK } from "jose";

const repoRoot = process.cwd();

// Canonicalization version pinning:
// - Increment ONLY when canonicalization logic changes.
// - Bundles signed with a different `canon` value will fail verification (fail-closed).
const CANON_VERSION = 1;

const DEFAULT_REGISTRY_PATH = path.join(repoRoot, "docs", "surfaces.registry.json");
const DEFAULT_BUNDLE_PATH = path.join(repoRoot, "docs", "surfaces.registry.bundle.json");

const isObject = (v) => Boolean(v) && typeof v === "object" && !Array.isArray(v);
const isNonEmptyString = (v) => typeof v === "string" && v.trim().length > 0;

const sortValue = (value) => {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === "object") {
    const record = value;
    return Object.keys(record)
      .sort()
      .reduce((acc, key) => {
        acc[key] = sortValue(record[key]);
        return acc;
      }, {});
  }
  return value;
};

const canonicalizeJson = (value) => JSON.stringify(sortValue(value));

const b64url = (input) => Buffer.from(input, "utf8").toString("base64url");

const parseSurfaceRegistry = (value) => {
  if (!isObject(value) || value.schemaVersion !== 1 || !Array.isArray(value.services)) {
    throw new Error("surface_registry_invalid");
  }
  // Basic schema validation (enough to prevent signing garbage).
  const allowedMethods = new Set(["GET", "POST", "PUT", "DELETE", "PATCH"]);
  const allowedSurfaces = new Set(["public", "internal", "admin", "dev_test_only"]);
  for (const svc of value.services) {
    if (!isObject(svc) || !isNonEmptyString(svc.id) || !Array.isArray(svc.routes)) {
      throw new Error("surface_registry_invalid");
    }
    for (const r of svc.routes) {
      if (!isObject(r)) throw new Error("surface_registry_invalid");
      const method = String(r.method ?? "").toUpperCase();
      const p = String(r.path ?? "");
      const surface = String(r.surface ?? "");
      if (!allowedMethods.has(method)) throw new Error("surface_registry_invalid");
      if (!p.startsWith("/")) throw new Error("surface_registry_invalid");
      if (!allowedSurfaces.has(surface)) throw new Error("surface_registry_invalid");
      if (r.disabledStatus !== undefined && r.disabledStatus !== 404 && r.disabledStatus !== 410) {
        throw new Error("surface_registry_invalid");
      }
      if (r.auth !== undefined && !isObject(r.auth)) throw new Error("surface_registry_invalid");
    }
  }
  return value;
};

const parseBase64urlJson = (encoded) => {
  const text = Buffer.from(encoded, "base64url").toString("utf8");
  return JSON.parse(text);
};

const encodeJwkForEnv = (jwk) => Buffer.from(JSON.stringify(jwk), "utf8").toString("base64url");

const loadRegistry = async (absPath) => {
  const raw = await readFile(absPath, "utf8");
  const parsed = JSON.parse(raw);
  return parseSurfaceRegistry(parsed);
};

const loadBundle = async (absPath) => {
  const raw = await readFile(absPath, "utf8");
  const parsed = JSON.parse(raw);
  if (!isObject(parsed) || !("registry" in parsed) || !("signature" in parsed)) {
    throw new Error("surface_registry_bundle_invalid");
  }
  const registry = parseSurfaceRegistry(parsed.registry);
  const sig = parsed.signature;
  if (
    !isObject(sig) ||
    !isNonEmptyString(sig.protected) ||
    !isNonEmptyString(sig.payload) ||
    !isNonEmptyString(sig.signature)
  ) {
    throw new Error("surface_registry_bundle_invalid");
  }
  return { registry, signature: sig };
};

const shouldRequireSignatureInCi = () => {
  if (process.env.CI !== "true") return false;
  const ref = process.env.GITHUB_REF ?? "";
  const refName = process.env.GITHUB_REF_NAME ?? "";
  // Enforce strictly on main branch pushes.
  return ref === "refs/heads/main" || refName === "main";
};

const parseArgs = (argv) => {
  const out = {
    help: false,
    verify: false,
    sync: false,
    registryPath: DEFAULT_REGISTRY_PATH,
    bundlePath: DEFAULT_BUNDLE_PATH
  };

  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--help" || a === "-h") {
      out.help = true;
      continue;
    }
    if (a === "--verify") {
      out.verify = true;
      continue;
    }
    if (a === "--sync") {
      out.sync = true;
      continue;
    }
    if (a === "--registry-path") {
      const v = argv[i + 1];
      if (!isNonEmptyString(v)) throw new Error("surface_registry_args_invalid");
      out.registryPath = path.resolve(repoRoot, v);
      i += 1;
      continue;
    }
    if (a === "--bundle-path") {
      const v = argv[i + 1];
      if (!isNonEmptyString(v)) throw new Error("surface_registry_args_invalid");
      out.bundlePath = path.resolve(repoRoot, v);
      i += 1;
      continue;
    }
    throw new Error(`surface_registry_args_unknown:${String(a)}`);
  }

  if (out.verify && out.sync) {
    throw new Error("surface_registry_args_invalid");
  }
  return out;
};

const protectedHeaderToDeterministicB64url = ({ kid, canon, legacy = false }) => {
  if (!isNonEmptyString(kid)) {
    throw new Error("surface_registry_kid_missing");
  }
  if (!legacy) {
    if (typeof canon !== "number" || !Number.isInteger(canon)) {
      throw new Error("surface_registry_integrity_failed");
    }
  }
  // Deterministic: only these fields; no timestamps; stable key insertion order.
  if (legacy) {
    return b64url(JSON.stringify({ alg: "EdDSA", typ: "surface-registry+json", kid }));
  }
  return b64url(JSON.stringify({ alg: "EdDSA", typ: "surface-registry+json", kid, canon }));
};

const parseAndValidateProtectedHeader = (protectedB64url) => {
  const header = parseBase64urlJson(protectedB64url);
  if (!isObject(header)) throw new Error("surface_registry_integrity_failed");

  const keys = Object.keys(header);
  const isLegacy = keys.length === 3 && keys.includes("alg") && keys.includes("typ") && keys.includes("kid");
  const isV1Plus = keys.length === 4 && keys.includes("alg") && keys.includes("typ") && keys.includes("kid") && keys.includes("canon");
  if (!isLegacy && !isV1Plus) {
    throw new Error("surface_registry_integrity_failed");
  }

  if (header.alg !== "EdDSA" || header.typ !== "surface-registry+json" || !isNonEmptyString(header.kid)) {
    throw new Error("surface_registry_integrity_failed");
  }

  const canon = (() => {
    if (isLegacy) {
      // Backwards-compat: pre-`canon` bundles are treated as canon=1.
      // Once canonicalization changes, bump CANON_VERSION and these will fail verification.
      if (CANON_VERSION !== 1) {
        throw new Error("surface_registry_canonicalization_version_mismatch");
      }
      return 1;
    }
    if (typeof header.canon !== "number" || !Number.isInteger(header.canon)) {
      throw new Error("surface_registry_integrity_failed");
    }
    if (header.canon !== CANON_VERSION) {
      throw new Error("surface_registry_canonicalization_version_mismatch");
    }
    return header.canon;
  })();

  const deterministic = protectedHeaderToDeterministicB64url({
    kid: header.kid,
    canon,
    legacy: isLegacy
  });
  if (protectedB64url !== deterministic) {
    // This catches manual edits like reordering header keys or adding extra fields.
    throw new Error("surface_registry_integrity_failed");
  }

  return { kid: header.kid, canon, legacy: isLegacy };
};

const verifyBundleSignature = async ({ bundle, publicKeyJwkB64url }) => {
  const compact = `${bundle.signature.protected}.${bundle.signature.payload}.${bundle.signature.signature}`;
  const jwk = parseBase64urlJson(publicKeyJwkB64url);
  const key = await importJWK(jwk, "EdDSA");
  await compactVerify(compact, key, { algorithms: ["EdDSA"] });
};

const buildExpectedBundleText = (input) => {
  const expectedRegistryObj = JSON.parse(input.canonicalRegistryText);
  const payloadB64 = b64url(input.canonicalRegistryText);
  const protectedB64 = protectedHeaderToDeterministicB64url({
    kid: input.kid,
    canon: input.canon,
    legacy: input.legacy
  });
  const expected = {
    registry: expectedRegistryObj,
    signature: {
      protected: protectedB64,
      payload: payloadB64,
      signature: input.signatureB64url
    }
  };
  return JSON.stringify(expected, null, 2) + "\n";
};

const main = async () => {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    // eslint-disable-next-line no-console
    console.log(`Usage:
  node scripts/security/sign-surface-registry.mjs [--verify|--sync] [--registry-path <path>] [--bundle-path <path>]

Modes:
  default (no flags): sign + write bundle (requires SURFACE_REGISTRY_PRIVATE_KEY)
  --verify: verify bundle deterministically (no writes)
  --sync: rewrite bundle to deterministic bytes (no signing; requires bundle already valid)
`);
    return;
  }

  const registry = await loadRegistry(args.registryPath);
  const canonicalRegistryText = canonicalizeJson(registry);

  const privateKeyEnv = String(process.env.SURFACE_REGISTRY_PRIVATE_KEY ?? "").trim();
  const publicKeyEnv = String(process.env.SURFACE_REGISTRY_PUBLIC_KEY ?? "").trim();
  const requireSignature = shouldRequireSignatureInCi();

  // If a public key is present, ensure `kid` matches the key (prevents confusing mixed-key states).
  const publicKid = (() => {
    if (!publicKeyEnv) return "";
    const jwk = parseBase64urlJson(publicKeyEnv);
    const kid = jwk && typeof jwk === "object" ? String(jwk.kid ?? "") : "";
    if (!isNonEmptyString(kid)) {
      throw new Error("surface_registry_public_key_invalid");
    }
    return kid;
  })();

  // Mode A: verify (no writes), or sync (normalize bundle bytes and write).
  if (args.verify || args.sync || !privateKeyEnv) {
    if (!existsSync(args.bundlePath)) {
      throw new Error("surface_registry_bundle_missing");
    }

    const bundleRaw = await readFile(args.bundlePath, "utf8");
    const bundle = await loadBundle(args.bundlePath);

    const { kid, canon, legacy } = parseAndValidateProtectedHeader(bundle.signature.protected);
    if (publicKid && kid !== publicKid) {
      throw new Error("surface_registry_integrity_failed");
    }

    // The signed payload must be EXACTLY the canonical JSON of the registry file (deterministic bytes).
    const expectedPayload = b64url(canonicalRegistryText);
    if (bundle.signature.payload !== expectedPayload) {
      throw new Error("surface_registry_bundle_registry_mismatch");
    }
    const payloadText = Buffer.from(bundle.signature.payload, "base64url").toString("utf8");
    if (payloadText !== canonicalRegistryText) {
      throw new Error("surface_registry_integrity_failed");
    }
    const payloadJson = JSON.parse(payloadText);
    if (canonicalizeJson(payloadJson) !== canonicalRegistryText) {
      throw new Error("surface_registry_integrity_failed");
    }

    // Optional (but required in production/CI main): verify the signature with the public key.
    if (!publicKeyEnv) {
      if (requireSignature) {
        throw new Error("surface_registry_public_key_missing");
      }
      if (args.verify || args.sync) {
        // eslint-disable-next-line no-console
        console.warn("[surface-registry] SURFACE_REGISTRY_PUBLIC_KEY missing; skipping signature verification");
      }
    } else {
      await verifyBundleSignature({ bundle, publicKeyJwkB64url: publicKeyEnv });
    }

    // Deterministic bundle bytes guard: the committed bundle must match exactly what we'd write.
    const expectedText = buildExpectedBundleText({
      canonicalRegistryText,
      kid,
      canon,
      legacy,
      signatureB64url: bundle.signature.signature
    });

    if (bundleRaw !== expectedText) {
      if (args.sync) {
        await writeFile(args.bundlePath, expectedText, "utf8");
        // eslint-disable-next-line no-console
        console.log(`[surface-registry] Synced bundle: ${path.relative(repoRoot, args.bundlePath)}`);
        return;
      }
      throw new Error("surface_registry_bundle_not_deterministic");
    }

    // eslint-disable-next-line no-console
    console.log("[surface-registry] verify OK");
    return;
  }

  // Mode 1: signing (requires a private JWK).
  const jwk = parseBase64urlJson(privateKeyEnv);
  if (!isObject(jwk) || !isNonEmptyString(jwk.d)) {
    throw new Error("surface_registry_private_key_invalid");
  }

  const { d, ...publicJwk } = jwk;
  void d;
  const kid = String(publicJwk.kid ?? "").trim();
  if (!isNonEmptyString(kid)) {
    throw new Error("surface_registry_kid_missing");
  }
  if (publicKid && kid !== publicKid) {
    throw new Error("surface_registry_public_key_kid_mismatch");
  }

  const key = await importJWK(jwk, "EdDSA");
  const jwsCompact = await new CompactSign(Buffer.from(canonicalRegistryText, "utf8"))
    // IMPORTANT: deterministic insertion order + pinned canonicalization version.
    .setProtectedHeader({ alg: "EdDSA", typ: "surface-registry+json", kid, canon: CANON_VERSION })
    .sign(key);

  const [prot, payload, sig] = String(jwsCompact).split(".");
  if (!prot || !payload || !sig) {
    throw new Error("surface_registry_signing_failed");
  }
  const expectedProt = protectedHeaderToDeterministicB64url({ kid, canon: CANON_VERSION, legacy: false });
  if (prot !== expectedProt) {
    throw new Error("surface_registry_signing_failed");
  }

  // Store the canonical registry object (deterministic key ordering) in the bundle.
  const bundle = {
    registry: JSON.parse(canonicalRegistryText),
    signature: { protected: prot, payload, signature: sig }
  };
  await writeFile(args.bundlePath, JSON.stringify(bundle, null, 2) + "\n", "utf8");

  // If caller didn't provide a public key, print a helper hint for exporting it.
  if (!publicKeyEnv) {
    // eslint-disable-next-line no-console
    console.log(`[surface-registry] Wrote bundle: ${path.relative(repoRoot, args.bundlePath)}`);
    // eslint-disable-next-line no-console
    console.log(`[surface-registry] Public key (base64url JWK) for SURFACE_REGISTRY_PUBLIC_KEY:`);
    // eslint-disable-next-line no-console
    console.log(encodeJwkForEnv(publicJwk));
  } else {
    // Best-effort self-check.
    await verifyBundleSignature({ bundle, publicKeyJwkB64url: publicKeyEnv });
    // eslint-disable-next-line no-console
    console.log(`[surface-registry] Signed + verified bundle: ${path.relative(repoRoot, args.bundlePath)}`);
  }
};

main().catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  // eslint-disable-next-line no-console
  console.error("[surface-registry] ERROR", message);
  process.exit(1);
});

