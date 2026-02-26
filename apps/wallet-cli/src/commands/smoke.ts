import { didCreate } from "./didCreate.js";
import { didResolve } from "./didResolve.js";

export const smoke = async () => {
  await didCreate();
  await didResolve();
};
