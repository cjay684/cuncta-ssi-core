import { log } from "./log.js";
import { config } from "./config.js";
import { buildServer } from "./server.js";
import { getDb } from "./db.js";

await getDb();
const app = buildServer();

app
  .listen({ port: config.PORT, host: config.SERVICE_BIND_ADDRESS })
  .then((address) => {
    log.info("listening", { address });
  })
  .catch((error) => {
    log.error("failed to start", { error });
    process.exit(1);
  });
