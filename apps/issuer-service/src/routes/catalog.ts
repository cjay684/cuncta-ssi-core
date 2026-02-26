import { FastifyInstance } from "fastify";
import { z } from "zod";
import { listCatalogEntries, getCatalogEntry } from "../catalog.js";
import { makeErrorResponse } from "@cuncta/shared";
import { config } from "../config.js";

export const registerCatalogRoutes = (app: FastifyInstance) => {
  app.get("/v1/catalog/credentials", async (_request, reply) => {
    let entries;
    try {
      entries = await listCatalogEntries();
    } catch (error) {
      if (error instanceof Error && error.message === "catalog_integrity_failed") {
        return reply.code(503).send(
          makeErrorResponse("catalog_integrity_failed", "Catalog integrity check failed", {
            devMode: config.DEV_MODE
          })
        );
      }
      throw error;
    }
    const enriched = entries.map((entry) => ({
      ...entry,
      lane: "sd-jwt-vc",
      sd_disclosure_defaults: entry.sd_defaults
    }));
    return reply.send(enriched);
  });

  app.get("/v1/catalog/credentials/:vct", async (request, reply) => {
    const params = z.object({ vct: z.string().min(1) }).parse(request.params);
    let entry;
    try {
      entry = await getCatalogEntry(params.vct);
    } catch (error) {
      if (error instanceof Error && error.message === "catalog_integrity_failed") {
        return reply.code(503).send(
          makeErrorResponse("catalog_integrity_failed", "Catalog integrity check failed", {
            devMode: config.DEV_MODE
          })
        );
      }
      throw error;
    }
    if (!entry) {
      return reply.code(404).send(
        makeErrorResponse("invalid_request", "Catalog entry not found", {
          devMode: config.DEV_MODE
        })
      );
    }
    return reply.send({
      ...entry,
      lane: "sd-jwt-vc",
      sd_disclosure_defaults: entry.sd_defaults
    });
  });
};
