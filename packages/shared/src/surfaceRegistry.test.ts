import { strict as assert } from "node:assert";
import {
  compileSurfaceRoutesForService,
  matchSurfaceRoute,
  type SurfaceRegistry
} from "./surfaceRegistry.js";

const run = () => {
  {
    const registry: SurfaceRegistry = {
      schemaVersion: 1,
      services: [
        {
          id: "svc",
          publiclyDeployable: true,
          routes: [
            { method: "GET", path: "/v1/social/*", surface: "internal" },
            { method: "GET", path: "/v1/social/post", surface: "public" }
          ]
        }
      ]
    };
    const compiled = compileSurfaceRoutesForService(registry, "svc");
    const matched = matchSurfaceRoute(compiled, { method: "GET", path: "/v1/social/post" });
    assert.ok(matched, "expected a match");
    assert.equal(matched.surface, "public", "exact match should override broader glob");
  }

  {
    const registry: SurfaceRegistry = {
      schemaVersion: 1,
      services: [
        {
          id: "svc",
          publiclyDeployable: true,
          routes: [
            { method: "GET", path: "/v1/*", surface: "internal" },
            { method: "GET", path: "/v1/social/*", surface: "public" }
          ]
        }
      ]
    };
    const compiled = compileSurfaceRoutesForService(registry, "svc");
    const matched = matchSurfaceRoute(compiled, { method: "GET", path: "/v1/social/xyz" });
    assert.ok(matched, "expected a match");
    assert.equal(
      matched.surface,
      "public",
      "more-specific glob should override less-specific glob"
    );
  }

  {
    const registry: SurfaceRegistry = {
      schemaVersion: 1,
      services: [
        {
          id: "svc",
          publiclyDeployable: true,
          routes: [
            { method: "POST", path: "/v1/onboard/*", surface: "public" },
            {
              method: "POST",
              path: "/v1/onboard/did/create/request",
              surface: "dev_test_only",
              disabledStatus: 410
            }
          ]
        }
      ]
    };
    const compiled = compileSurfaceRoutesForService(registry, "svc");
    const matched = matchSurfaceRoute(compiled, {
      method: "POST",
      path: "/v1/onboard/did/create/request"
    });
    assert.ok(matched, "expected a match");
    assert.equal(matched.surface, "dev_test_only", "exact match should override glob");
    assert.equal(matched.disabledStatus, 410);
  }
};

try {
  run();
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
