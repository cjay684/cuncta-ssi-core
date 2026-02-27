import {
  didCreate,
  didCreateAuto,
  didCreateUserPays,
  didCreateUserPaysGateway
} from "./commands/didCreate.js";
import { didResolve } from "./commands/didResolve.js";
import { didRotate } from "./commands/didRotate.js";
import { didDeactivate } from "./commands/didDeactivate.js";
import {
  didRecoveryRotate,
  didRecoverySetup,
  didRecoverySimulateLoss
} from "./commands/didRecovery.js";
import { smoke } from "./commands/smoke.js";
import { smokeFull } from "./commands/smokeFull.js";
import { vcIssueAge } from "./commands/vcIssueAge.js";
import { presentAge } from "./commands/presentAge.js";
import { smokeStrict } from "./commands/smokeStrict.js";
import { issueRequest } from "./commands/issueRequest.js";
import { present } from "./commands/present.js";
import { verify } from "./commands/verify.js";
import { vcAcquire } from "./commands/vcAcquire.js";
import { vpRespond } from "./commands/vpRespond.js";
import { auraSimulate } from "./commands/auraSimulate.js";
import { auraClaim } from "./commands/auraClaim.js";
import { coreSmoke } from "./commands/coreSmoke.js";
import { privacyKbjwt } from "./commands/privacyKbjwt.js";
import { privacyFlow } from "./commands/privacyFlow.js";
import "./config.js";

// Phase 0 guard: CI-only flag must never be used in production.
if ((process.env.CI_TEST_MODE ?? "").trim() === "true") {
  const nodeEnv = (process.env.NODE_ENV ?? "development").trim();
  if (nodeEnv === "production") {
    throw new Error("ci_test_mode_forbidden_in_production");
  }
}

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
if (command) {
  // Early pre-dispatch liveness marker for harness no-output detection.
  process.stdout.write(`stage=wallet.cli|event=dispatch|command=${command}\n`);
}

const run = async () => {
  if (command === "did:create") {
    await didCreate();
    return;
  }
  if (command === "did:create:auto") {
    const args = process.argv.slice(3);
    const modeIndex = args.findIndex((arg) => arg === "--mode");
    const mode = modeIndex === -1 ? undefined : args[modeIndex + 1];
    if (mode && mode !== "user_pays") {
      throw new Error(
        "Invalid --mode (expected user_pays). CUNCTA supports self-funded onboarding only."
      );
    }
    await didCreateAuto(mode as "user_pays" | undefined);
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
  if (command === "did:rotate") {
    await didRotate();
    return;
  }
  if (command === "did:recovery:setup") {
    await didRecoverySetup();
    return;
  }
  if (command === "did:recovery:simulate-loss") {
    await didRecoverySimulateLoss();
    return;
  }
  if (command === "did:recovery:rotate") {
    await didRecoveryRotate();
    return;
  }
  if (command === "did:deactivate") {
    await didDeactivate();
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
  if (command === "vc:acquire") {
    await vcAcquire();
    return;
  }
  if (command === "vp:respond") {
    await vpRespond();
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
  console.log("  did:create:auto --mode user_pays  Self-funded onboarding (default)");
  console.log("  did:create:user-pays  Create DID using payer credentials");
  console.log("  did:create:user-pays-gateway  Create DID via gateway user-pays");
  console.log("  did:resolve Resolve the stored DID");
  console.log("  did:rotate Rotate DID root key (self-funded)");
  console.log("  did:recovery:setup Install recovery key on DID");
  console.log("  did:recovery:simulate-loss Remove primary key locally");
  console.log("  did:recovery:rotate Rotate DID using recovery key");
  console.log("  did:deactivate Deactivate DID (self-funded)");
  console.log("  smoke       Run did:create then did:resolve");
  console.log("  smoke:full  End-to-end smoke flow across services");
  console.log("  vc:issue:age Issue age_over_18 credential");
  console.log("  present:age Present age_over_18 credential");
  console.log("  smoke:strict Strict SD-JWT KB-JWT flow");
  console.log("  issue:request Issue marketplace.list_item credential");
  console.log("  present      Build presentation for an action");
  console.log("  verify       Verify last presentation for action");
  console.log("  vc:acquire   Acquire credential via OID4VCI");
  console.log("  vp:respond   Respond to OID4VP request via gateway");
  console.log("  aura:simulate Loop present+verify to emit aura signals");
  console.log("  aura:claim    Claim derived aura credential if ready");
  console.log("  core:smoke    Run full core smoke flow");
  console.log("  privacy:kbjwt Generate a KB-JWT for DSR confirm");
  console.log("  privacy:flow  Run DSR request+confirm demo flow");
};

run()
  .then(() => {
    // Some commands (notably OIDC/JWKS flows) can leave handles alive in dependencies.
    // wallet-cli is a one-shot tool, so force success exit once command completes.
    process.exit(0);
  })
  .catch((error) => {
    if (error instanceof Error) {
      const wantStack = process.env.WALLET_DEBUG_STACK === "1";
      console.error(wantStack ? (error.stack ?? error.message) : error.message);
    } else {
      console.error(String(error));
    }
    process.exit(1);
  });
