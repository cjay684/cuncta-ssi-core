import { FastifyInstance } from "fastify";
import { GatewayContext } from "../server.js";

const ipAllowed = (ip: string | undefined, context: GatewayContext, limitPerMinute: number) => {
  const key = context.hashValue(ip ?? "unknown");
  return context.ipQuotaMinute.consume(key, limitPerMinute, 60_000);
};

export const registerCapabilitiesRoutes = (app: FastifyInstance, context: GatewayContext) => {
  app.get(
    "/v1/capabilities",
    {
      config: {
        rateLimit: {
          max: context.config.RATE_LIMIT_IP_DEFAULT_PER_MIN,
          timeWindow: "1 minute"
        }
      }
    },
    async (request, reply) => {
      if (!ipAllowed(request.ip, context, context.config.RATE_LIMIT_IP_DEFAULT_PER_MIN)) {
        return reply.code(429).send({
          error: "rate_limited",
          message: "IP rate limit exceeded"
        });
      }
      return reply.send({
        selfFundedOnboarding: {
          enabled: context.config.ALLOW_SELF_FUNDED_ONBOARDING,
          maxFeeTinybars: context.config.USER_PAYS_MAX_FEE_TINYBARS,
          maxTxBytes: context.config.USER_PAYS_MAX_TX_BYTES,
          requestTtlSeconds: context.config.USER_PAYS_REQUEST_TTL_SECONDS
        },
        network: context.config.HEDERA_NETWORK,
        requirements: { requireDeviceId: context.config.REQUIRE_DEVICE_ID_FOR_REQUIREMENTS }
      });
    }
  );
};
