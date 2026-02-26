import { FastifyReply, FastifyRequest } from "fastify";
export declare const requireServiceAuth: (
  request: FastifyRequest,
  reply: FastifyReply
) => Promise<void>;
