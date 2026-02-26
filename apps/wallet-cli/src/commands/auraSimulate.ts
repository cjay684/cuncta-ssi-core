import { present } from "./present.js";
import { verify } from "./verify.js";

export const auraSimulate = async (action = "dev.aura.signal", count = 3) => {
  const total = Number.isFinite(count) ? count : 3;
  for (let i = 0; i < total; i += 1) {
    await present(action);
    await verify(action);
  }
  console.log(`aura_simulated=${total}`);
};
