import { workerData } from "node:worker_threads";
import { pathToFileURL } from "node:url";

const fail = (error) => {
  if (error instanceof Error) {
    console.error(error.stack ?? error.message);
  } else {
    console.error(error);
  }
  process.exit(1);
};

process.on("unhandledRejection", fail);
process.on("uncaughtException", fail);

import(pathToFileURL(workerData.file).href).catch(fail);
