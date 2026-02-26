import { FastifyInstance } from "fastify";
import { config } from "../config.js";

export const registerHealthRoutes = (app: FastifyInstance) => {
  app.get("/healthz", async () => {
    return {
      ok: true,
      serviceAuth: {
        audience: config.SERVICE_JWT_AUDIENCE,
        ttlSeconds: config.SERVICE_JWT_TTL_SECONDS
      },
      gateway: {
        allowedVcts: config.GATEWAY_ALLOWED_VCTS,
        verifierEnabled: Boolean(config.VERIFIER_SERVICE_BASE_URL),
        policyEnabled: Boolean(config.POLICY_SERVICE_BASE_URL)
      },
      limits: {
        bodyLimitBytes: config.BODY_LIMIT_BYTES,
        ipDefaultPerMin: config.RATE_LIMIT_IP_DEFAULT_PER_MIN,
        ipDidRequestPerMin: config.RATE_LIMIT_IP_DID_REQUEST_PER_MIN,
        ipDidSubmitPerMin: config.RATE_LIMIT_IP_DID_SUBMIT_PER_MIN,
        ipIssuePerMin: config.RATE_LIMIT_IP_ISSUE_PER_MIN,
        ipVerifyPerMin: config.RATE_LIMIT_IP_VERIFY_PER_MIN,
        deviceDidPerDay: config.RATE_LIMIT_DEVICE_DID_PER_DAY,
        deviceIssuePerMin: config.RATE_LIMIT_DEVICE_ISSUE_PER_MIN
      }
    };
  });
};
