import fastify from "fastify";
export declare const buildServer: () => fastify.FastifyInstance<
  import("node:http").Server<
    typeof import("node:http").IncomingMessage,
    typeof import("node:http").ServerResponse
  >,
  import("node:http").IncomingMessage,
  import("node:http").ServerResponse<import("node:http").IncomingMessage>,
  fastify.FastifyBaseLogger,
  fastify.FastifyTypeProviderDefault
> &
  PromiseLike<
    fastify.FastifyInstance<
      import("node:http").Server<
        typeof import("node:http").IncomingMessage,
        typeof import("node:http").ServerResponse
      >,
      import("node:http").IncomingMessage,
      import("node:http").ServerResponse<import("node:http").IncomingMessage>,
      fastify.FastifyBaseLogger,
      fastify.FastifyTypeProviderDefault
    >
  > & {
    __linterBrands: "SafePromiseLike";
  };
