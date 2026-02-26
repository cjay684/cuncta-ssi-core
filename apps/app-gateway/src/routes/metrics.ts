import { FastifyInstance } from "fastify";
import { metrics } from "../metrics.js";
import { config } from "../config.js";

export const registerMetricsRoutes = (app: FastifyInstance) => {
  app.get("/metrics", async (_request, reply) => {
    metrics.setGauge("backup_restore_mode_active", {}, config.BACKUP_RESTORE_MODE ? 1 : 0);
    reply.header("content-type", "text/plain; version=0.0.4");
    return metrics.render();
  });
};
