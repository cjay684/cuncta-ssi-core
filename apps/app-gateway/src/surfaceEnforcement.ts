import path from "node:path";
import { fileURLToPath } from "node:url";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import {
  extractBearerToken,
  compileSurfaceRoutesForService,
  loadSurfaceRegistryForRuntime,
  matchSurfaceRoute,
  makeErrorResponse,
  verifyServiceJwt,
  type CompiledSurfaceRoute
} from "@cuncta/shared";
import { log } from "./log.js";

const repoRootFromThisFile = () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(here, "..", "..", "..");
};

const resolveRegistryPaths = () => {
  const repoRoot = repoRootFromThisFile();
  const defaultRegistryPath = path.join(repoRoot, "docs", "surfaces.registry.json");
  const defaultBundlePath = path.join(repoRoot, "docs", "surfaces.registry.bundle.json");

  const override =
    process.env.SURFACE_REGISTRY_PATH && String(process.env.SURFACE_REGISTRY_PATH).trim().length > 0
      ? String(process.env.SURFACE_REGISTRY_PATH).trim()
      : "";

  // Backward compatible:
  // - If SURFACE_REGISTRY_PATH points at a .bundle.json, treat it as a bundle override.
  // - Otherwise treat it as an unsigned registry override.
  if (override.endsWith(".bundle.json")) {
    return { registryPath: defaultRegistryPath, bundlePath: override };
  }
  if (override) {
    return { registryPath: override, bundlePath: defaultBundlePath };
  }
  return { registryPath: defaultRegistryPath, bundlePath: defaultBundlePath };
};

// In public production posture, keep auth failures generic (no token/scope/service details).
const unauthorized = (reply: FastifyReply, devMode: boolean) =>
  reply.code(401).send(makeErrorResponse("invalid_request", "unauthorized", { devMode }));

const forbid = (reply: FastifyReply, devMode: boolean) =>
  reply.code(403).send(makeErrorResponse("forbidden", "forbidden", { devMode }));

export const registerSurfaceEnforcement = (
  app: FastifyInstance,
  input: {
  config: {
    NODE_ENV: string;
    PUBLIC_SERVICE: boolean;
    DEV_MODE: boolean;
    SERVICE_JWT_SECRET?: string;
    SERVICE_JWT_AUDIENCE: string;
  };
}
) => {
  const enabled = input.config.NODE_ENV === "production" && input.config.PUBLIC_SERVICE;
  const { registryPath, bundlePath } = resolveRegistryPaths();
  const publicKey = process.env.SURFACE_REGISTRY_PUBLIC_KEY;

  let compiled: CompiledSurfaceRoute[] = [];

  app.addHook("onReady", async () => {
    const registry = await loadSurfaceRegistryForRuntime({
      nodeEnv: input.config.NODE_ENV,
      bundlePath,
      registryPath,
      publicKeyJwkBase64url: publicKey,
      logger: {
        warn: (event, meta) => log.warn(event, meta)
      }
    });
    if (enabled) {
      compiled = compileSurfaceRoutesForService(registry, "app-gateway");
      if (compiled.length === 0) {
        throw new Error("surface_registry_missing_service:app-gateway");
      }
    }
  });

  app.addHook("preHandler", async (request: FastifyRequest, reply: FastifyReply) => {
    if (!enabled) return;

    const routePath = request.routeOptions?.url ?? request.url.split("?")[0];
    const matched = matchSurfaceRoute(compiled, { method: request.method, path: routePath });

    // Fail closed: if a route exists in code but isn't in the registry, public posture blocks it.
    if (!matched) {
      return reply
        .code(404)
        .send(makeErrorResponse("not_found", "not found", { devMode: input.config.DEV_MODE }));
    }

    if (matched.surface === "dev_test_only") {
      const status = matched.disabledStatus === 410 ? 410 : 404;
      const message = status === 410 ? "gone" : "not found";
      return reply
        .code(status)
        .send(makeErrorResponse("not_found", message, { devMode: input.config.DEV_MODE }));
    }

    if (matched.surface !== "internal" && matched.surface !== "admin") {
      return;
    }

    const secret = input.config.SERVICE_JWT_SECRET;
    if (!secret) {
      return reply.code(503).send(
        makeErrorResponse("service_auth_unavailable", "service unavailable", {
          devMode: input.config.DEV_MODE
        })
      );
    }

    const token = extractBearerToken(request.headers.authorization);
    if (!token) {
      return unauthorized(reply, input.config.DEV_MODE);
    }

    try {
      await verifyServiceJwt(token, {
        audience: input.config.SERVICE_JWT_AUDIENCE,
        secret,
        requiredScopes: matched.surface === "internal" ? matched.auth?.requiredScopes : undefined,
        requireAdminScope: matched.surface === "admin" ? matched.auth?.requireAdminScope : undefined
      });
      return;
    } catch (error) {
      if (error instanceof Error && error.message === "jwt_missing_required_scope") {
        return forbid(reply, input.config.DEV_MODE);
      }
      return unauthorized(reply, input.config.DEV_MODE);
    }
  });
};

