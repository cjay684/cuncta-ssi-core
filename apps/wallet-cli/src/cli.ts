import {
  didCreate,
  didCreateAuto,
  didCreateUserPays,
  didCreateUserPaysGateway
} from "./commands/didCreate.js";
import { didResolve } from "./commands/didResolve.js";
import { smoke } from "./commands/smoke.js";
import { smokeFull } from "./commands/smokeFull.js";
import { vcIssueAge } from "./commands/vcIssueAge.js";
import { presentAge } from "./commands/presentAge.js";
import { smokeStrict } from "./commands/smokeStrict.js";
import { issueRequest } from "./commands/issueRequest.js";
import { present } from "./commands/present.js";
import { verify } from "./commands/verify.js";
import { auraSimulate } from "./commands/auraSimulate.js";
import { auraClaim } from "./commands/auraClaim.js";
import { coreSmoke } from "./commands/coreSmoke.js";
import { privacyKbjwt } from "./commands/privacyKbjwt.js";
import { privacyFlow } from "./commands/privacyFlow.js";
import "./config.js";

if (!process.env.NO_PROXY) {
  process.env.NO_PROXY = "localhost,127.0.0.1";
} else if (!process.env.NO_PROXY.includes("localhost")) {
  process.env.NO_PROXY = `${process.env.NO_PROXY},localhost,127.0.0.1`;
}
if (process.env.HTTP_PROXY) {
  process.env.HTTP_PROXY = "";
}
if (process.env.HTTPS_PROXY) {
  process.env.HTTPS_PROXY = "";
}
if (process.env.ALL_PROXY) {
  process.env.ALL_PROXY = "";
}
if (process.env.http_proxy) {
  process.env.http_proxy = "";
}
if (process.env.https_proxy) {
  process.env.https_proxy = "";
}
if (process.env.all_proxy) {
  process.env.all_proxy = "";
}

const [command] = process.argv.slice(2);

const run = async () => {
  if (command === "did:create") {
    await didCreate();
    return;
  }
  if (command === "did:create:auto") {
    const args = process.argv.slice(3);
    const modeIndex = args.findIndex((arg) => arg === "--mode");
    const mode = modeIndex === -1 ? undefined : args[modeIndex + 1];
    if (mode && mode !== "sponsored" && mode !== "user_pays") {
      throw new Error("Invalid --mode (expected sponsored|user_pays)");
    }
    await didCreateAuto(mode as "sponsored" | "user_pays" | undefined);
    return;
  }
  if (command === "did:create:user-pays") {
    await didCreateUserPays();
    return;
  }
  if (command === "did:create:user-pays-gateway") {
    await didCreateUserPaysGateway();
    return;
  }
  if (command === "did:resolve") {
    await didResolve();
    return;
  }
  if (command === "smoke") {
    await smoke();
    return;
  }
  if (command === "smoke:full") {
    await smokeFull();
    return;
  }
  if (command === "vc:issue:age") {
    await vcIssueAge();
    return;
  }
  if (command === "present:age") {
    await presentAge();
    return;
  }
  if (command === "smoke:strict") {
    await smokeStrict();
    return;
  }
  if (command === "issue:request") {
    await issueRequest();
    return;
  }
  if (command === "present") {
    await present(process.argv[3]);
    return;
  }
  if (command === "verify") {
    await verify(process.argv[3]);
    return;
  }
  if (command === "aura:simulate") {
    const action = process.argv[3];
    const count = Number(process.argv[4] ?? 3);
    await auraSimulate(action, count);
    return;
  }
  if (command === "aura:claim") {
    await auraClaim(process.argv[3]);
    return;
  }
  if (command === "core:smoke") {
    await coreSmoke();
    return;
  }
  if (command === "privacy:kbjwt") {
    const args = process.argv.slice(3);
    const getArg = (name: string) => {
      const index = args.findIndex((arg) => arg === name);
      if (index === -1) return undefined;
      return args[index + 1];
    };
    await privacyKbjwt({
      requestId: getArg("--requestId"),
      nonce: getArg("--nonce"),
      audience: getArg("--audience")
    });
    return;
  }
  if (command === "privacy:flow") {
    await privacyFlow();
    return;
  }

  console.log("wallet-cli commands:");
  console.log("  did:create  Create a did:hedera using default onboarding");
  console.log("  did:create:auto --mode sponsored|user_pays  Select onboarding strategy");
  console.log("  did:create:user-pays  Create DID using payer credentials");
  console.log("  did:create:user-pays-gateway  Create DID via gateway user-pays");
  console.log("  did:resolve Resolve the stored DID");
  console.log("  smoke       Run did:create then did:resolve");
  console.log("  smoke:full  End-to-end smoke flow across services");
  console.log("  vc:issue:age Issue age_over_18 credential");
  console.log("  present:age Present age_over_18 credential");
  console.log("  smoke:strict Strict SD-JWT KB-JWT flow");
  console.log("  issue:request Issue marketplace.list_item credential");
  console.log("  present      Build presentation for an action");
  console.log("  verify       Verify last presentation for action");
  console.log("  aura:simulate Loop present+verify to emit aura signals");
  console.log("  aura:claim    Claim derived aura credential if ready");
  console.log("  core:smoke    Run full core smoke flow");
  console.log("  privacy:kbjwt Generate a KB-JWT for DSR confirm");
  console.log("  privacy:flow  Run DSR request+confirm demo flow");
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
