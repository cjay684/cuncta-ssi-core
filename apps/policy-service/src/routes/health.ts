import { FastifyInstance } from "fastify";
import { metrics } from "../metrics.js";
import { config } from "../config.js";
import { getDb, isDbReady } from "../db.js";

export const registerHealthRoutes = (app: FastifyInstance) => {
  app.get("/healthz", async (_request, reply) => {
    // Health is only OK once DB migrations + baseline policy bootstrap have completed.
    // This keeps callers from receiving "requirements_unavailable" due to missing seed data.
    if (!isDbReady()) {
      // Kick initialization but don't block the health endpoint.
      void getDb().catch(() => null);
      return reply.code(503).send({ ok: false, error: "not_ready" });
    }
    return { ok: true };
  });
  app.get("/metrics", async (_request, reply) => {
    metrics.setGauge("backup_restore_mode_active", {}, config.BACKUP_RESTORE_MODE ? 1 : 0);
    reply.header("content-type", "text/plain; version=0.0.4");
    return reply.send(metrics.render());
  });
};
