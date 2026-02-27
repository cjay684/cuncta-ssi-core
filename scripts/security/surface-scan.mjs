import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

const repoRoot = process.cwd();

const REGISTRY_PATH = path.join(repoRoot, "docs", "surfaces.registry.json");
const BUNDLE_PATH = path.join(repoRoot, "docs", "surfaces.registry.bundle.json");

const SERVICES = [
  { id: "app-gateway", routesDir: "apps/app-gateway/src/routes" },
  { id: "issuer-service", routesDir: "apps/issuer-service/src/routes" }
  // did-service / verifier-service / policy-service / social-service are private in production;
  // this scan focuses on consumer/public + issuer metadata surfaces tracked in docs/surfaces.md.
];

const rel = (abs) => path.relative(repoRoot, abs).replaceAll("\\", "/");

const isTextFile = (p) => [".ts", ".js", ".mjs", ".cjs"].includes(path.extname(p).toLowerCase());

const isObject = (v) => Boolean(v) && typeof v === "object" && !Array.isArray(v);

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

const walkFiles = async (dir) => {
  const out = [];
  const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === "node_modules" || e.name === "dist") continue;
      out.push(...(await walkFiles(full)));
    } else if (e.isFile() && isTextFile(full)) {
      out.push(full);
    }
  }
  return out;
};

const parseDocs = async () => {
  const docPath = path.join(repoRoot, "docs", "surfaces.md");
  const markdown = await readFile(docPath, "utf8");
  const byHeading = new Map();
  const lines = markdown.split("\n");
  let current = "";
  for (const line of lines) {
    const h = line.match(/^###\s+(.+)\s*$/);
    if (h) {
      current = String(h[1] ?? "").trim();
      if (!byHeading.has(current)) byHeading.set(current, []);
      continue;
    }
    const m = line.match(/`(GET|POST|PUT|DELETE|PATCH)\s+([^`]+)`/);
    if (!m || !current) continue;
    byHeading.get(current).push({ method: m[1], path: String(m[2]).trim() });
  }
  return { docPath, byHeading };
};

const parseRegistry = async () => {
  const raw = await readFile(REGISTRY_PATH, "utf8");
  const parsed = JSON.parse(raw);
  if (!parsed || typeof parsed !== "object") {
    throw new Error("surface_registry_invalid_json");
  }
  const schemaVersion = Number(parsed.schemaVersion);
  if (schemaVersion !== 1) {
    throw new Error(`surface_registry_schema_unsupported:${String(parsed.schemaVersion)}`);
  }
  const services = Array.isArray(parsed.services) ? parsed.services : [];
  return {
    registryPath: REGISTRY_PATH,
    services
  };
};

const verifyBundlePayloadMatchesRegistry = async () => {
  // Extra hardening: ensure the signed bundle cannot drift from the unsigned registry.
  // This check is intentionally strict: the payload must be the canonical JSON bytes of the registry file.
  const registryRaw = await readFile(REGISTRY_PATH, "utf8");
  const registryJson = JSON.parse(registryRaw);
  const canonicalRegistry = canonicalizeJson(registryJson);

  const bundleRaw = await readFile(BUNDLE_PATH, "utf8");
  const bundleJson = JSON.parse(bundleRaw);
  if (
    !isObject(bundleJson) ||
    !isObject(bundleJson.signature) ||
    typeof bundleJson.signature.payload !== "string"
  ) {
    throw new Error("surface_registry_bundle_invalid");
  }

  const payloadText = Buffer.from(String(bundleJson.signature.payload), "base64url").toString(
    "utf8"
  );
  if (payloadText !== canonicalRegistry) {
    throw new Error("surface_registry_bundle_registry_mismatch");
  }

  const payloadJson = JSON.parse(payloadText);
  if (canonicalizeJson(payloadJson) !== canonicalRegistry) {
    throw new Error("surface_registry_bundle_registry_mismatch");
  }
};

const docRoutesForService = (byHeading, serviceId) => {
  const out = [];
  for (const [heading, routes] of byHeading.entries()) {
    const h = String(heading);
    if (h === serviceId || h.startsWith(`${serviceId} `) || h.startsWith(`${serviceId} (`)) {
      out.push(...routes);
    }
  }
  return out;
};

const registryRoutesForService = (registryServices, serviceId) => {
  const service = registryServices.find((s) => s && typeof s === "object" && s.id === serviceId);
  const routes = service && Array.isArray(service.routes) ? service.routes : [];
  return routes
    .map((r) => ({
      method: String(r.method ?? "")
        .trim()
        .toUpperCase(),
      path: String(r.path ?? "").trim(),
      surface: String(r.surface ?? "").trim(),
      probe: r && typeof r === "object" ? r.probe : undefined
    }))
    .filter(
      (r) => ["GET", "POST", "PUT", "DELETE", "PATCH"].includes(r.method) && r.path.startsWith("/")
    );
};

const extractRoutesFromCode = async (service) => {
  const dir = path.join(repoRoot, service.routesDir);
  const files = await walkFiles(dir);
  const found = new Set();

  const reSimple = /\bapp\.(get|post|put|delete|patch)\(\s*["']([^"']+)["']/g;
  const reRouteObj =
    /\bapp\.route\(\s*\{\s*method:\s*["'](GET|POST|PUT|DELETE|PATCH)["']\s*,\s*(url|path):\s*["']([^"']+)["']/g;

  for (const file of files) {
    const content = await readFile(file, "utf8").catch(() => "");
    for (const match of content.matchAll(reSimple)) {
      const method = String(match[1] ?? "").toUpperCase();
      const p = String(match[2] ?? "").trim();
      if (!p.startsWith("/")) continue;
      found.add(`${method} ${p}`);
    }
    for (const match of content.matchAll(reRouteObj)) {
      const method = String(match[1] ?? "").toUpperCase();
      const p = String(match[3] ?? "").trim();
      if (!p.startsWith("/")) continue;
      found.add(`${method} ${p}`);
    }
  }
  return { files: files.map(rel), routes: Array.from(found).sort() };
};

const escapeRegex = (value) => value.replace(/[.+?^${}()|[\]\\]/g, "\\$&");

const compileRoutePattern = (r) => {
  // Supported pattern syntax (shared by docs + registry):
  // - `*` suffix/prefix wildcard (matches any chars, including slashes)
  // - `:param` fastify-style params (matches one path segment)
  const rawPath = r.path;
  let out = "";
  for (let i = 0; i < rawPath.length; i += 1) {
    const ch = rawPath[i];
    if (ch === "*") {
      out += ".*";
      continue;
    }
    if (ch === ":") {
      // consume param name
      let j = i + 1;
      while (j < rawPath.length) {
        const c = rawPath[j];
        if (!/[A-Za-z0-9_]/.test(c)) break;
        j += 1;
      }
      // If ":" is not followed by an identifier, treat literally.
      if (j === i + 1) {
        out += escapeRegex(ch);
      } else {
        out += "[^/]+";
        i = j - 1;
      }
      continue;
    }
    out += escapeRegex(ch);
  }
  return {
    raw: `${r.method} ${r.path}`,
    method: r.method,
    re: new RegExp(`^${r.method}\\s+${out}$`)
  };
};

const main = async () => {
  const failures = [];
  const { docPath, byHeading } = await parseDocs();
  const { registryPath, services: registryServices } = await parseRegistry();

  // Fail early on bundle drift or manual edits to the signed payload.
  await verifyBundlePayloadMatchesRegistry();

  for (const service of SERVICES) {
    const docRoutesRaw = docRoutesForService(byHeading, service.id);
    if (!docRoutesRaw.length) {
      failures.push({
        kind: "docs_missing_service",
        detail: `docs/surfaces.md missing routes under a heading starting with: ### ${service.id}`
      });
    }

    const registryService = registryServices.find(
      (s) => s && typeof s === "object" && s.id === service.id
    );
    const publiclyDeployable = Boolean(
      registryService && registryService.publiclyDeployable === true
    );
    const assertNoDevTestOnlyRoutes = Boolean(
      registryService && registryService.assertNoDevTestOnlyRoutes === true
    );

    const registryRoutesRaw = registryRoutesForService(registryServices, service.id);
    if (!registryRoutesRaw.length) {
      failures.push({
        kind: "registry_missing_service",
        detail: `docs/surfaces.registry.json missing routes for service id: ${service.id}`
      });
      continue;
    }

    // docs/surfaces.md is human-facing, but must stay consistent with the registry.
    // We compare the literal route patterns (METHOD + path), not the expanded code routes.
    const docSet = new Set(docRoutesRaw.map((r) => `${r.method} ${r.path}`));
    const registrySet = new Set(registryRoutesRaw.map((r) => `${r.method} ${r.path}`));
    for (const entry of docSet) {
      if (!registrySet.has(entry)) {
        failures.push({ kind: "docs_not_in_registry", detail: `${service.id}: ${entry}` });
      }
    }

    // For publicly deployable services, ensure public routes are always probe-able by runtime tests.
    if (publiclyDeployable) {
      for (const r of registryRoutesRaw) {
        if (r.surface !== "public") continue;
        const probePath = r.probe && typeof r.probe === "object" ? String(r.probe.path ?? "") : "";
        if (!probePath.startsWith("/")) {
          failures.push({
            kind: "public_route_missing_probe",
            detail: `${service.id}: ${r.method} ${r.path} (missing probe.path)`
          });
        }
      }
      const hasDevTestOnly = registryRoutesRaw.some((r) => r.surface === "dev_test_only");
      if (!hasDevTestOnly && !assertNoDevTestOnlyRoutes) {
        failures.push({
          kind: "dev_test_only_expectation_missing",
          detail: `${service.id}: publiclyDeployable=true but no dev_test_only routes found (set assertNoDevTestOnlyRoutes=true if intentional)`
        });
      }
    }

    const code = await extractRoutesFromCode(service);
    const codeRoutes = code.routes;
    const registryRoutes = registryRoutesRaw.map(compileRoutePattern);

    // Every code route must be documented (exact or glob match).
    for (const route of codeRoutes) {
      const [method] = route.split(" ");
      const ok = registryRoutes.some((d) => d.method === method && d.re.test(route));
      if (!ok) {
        failures.push({ kind: "route_missing_from_registry", detail: `${service.id}: ${route}` });
      }
    }

    // Registry freshness:
    // - Every registry entry must match at least one code route, OR be a documented glob pattern.
    //   (Allows intentionally broad globs that are hard to extract from code, while still preventing typos/drift.)
    for (const d of registryRoutes) {
      const ok = codeRoutes.some((r) => d.re.test(r));
      if (ok) continue;

      const [method, ...rest] = d.raw.split(" ");
      const p = rest.join(" ").trim();
      const isGlob = p.includes("*");
      const isDocumentedGlob = isGlob && docSet.has(d.raw);
      if (!isDocumentedGlob) {
        failures.push({
          kind: "registry_route_matches_nothing",
          detail: `${service.id}: ${d.raw} (no matching code route; not a documented glob)`
        });
      }
    }
  }

  if (failures.length) {
    console.error("[surface-scan] FAIL");
    console.error(`docs=${docPath}`);
    console.error(`registry=${registryPath}`);
    for (const f of failures.slice(0, 100)) {
      console.error(`- ${f.kind}: ${f.detail}`);
    }
    if (failures.length > 100) {
      console.error(`... (${failures.length - 100} more)`);
    }
    process.exit(1);
  }

  console.log("[surface-scan] OK");
};

main().catch((err) => {
  console.error("[surface-scan] ERROR", err instanceof Error ? err.message : err);
  process.exit(2);
});
