import path from "node:path";
import { mkdir, writeFile, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync, spawn } from "node:child_process";
import { createRequire } from "node:module";
import { rm } from "node:fs/promises";

const require = createRequire(import.meta.url);

const repoRoot = path.resolve(process.cwd(), "..", "..");
const pkgDir = path.join(repoRoot, "packages", "zk-age-snark");
const circuitsDir = path.join(pkgDir, "circuits");
const outDir = path.join(pkgDir, "artifacts", "age_gte_v1");

const sha256Hex = async (p) =>
  createHash("sha256")
    .update(await readFile(p))
    .digest("hex");

const run = (label, cmd, args, cwd, options = {}) => {
  const started = Date.now();
  const timeoutMs = typeof options.timeoutMs === "number" ? options.timeoutMs : 30 * 60 * 1000;
  const shell = typeof options.shell === "boolean" ? options.shell : false;
  console.log(`\n[artifacts] step=${label}`);
  console.log(`[artifacts] cwd=${cwd}`);
  console.log(`[artifacts] cmd=${cmd} ${args.join(" ")}`);
  const res = spawnSync(cmd, args, {
    cwd,
    // Avoid "inherit" on Windows for long-running tools; we've seen cases where
    // it can block/hang after the child finished writing output.
    stdio: ["ignore", "pipe", "pipe"],
    // Default to no shell. Shelling out on Windows can introduce cmd.exe edge cases
    // (including "finished but never returns" behavior for .cmd wrappers).
    shell,
    windowsHide: true,
    timeout: timeoutMs
  });
  if (res.stdout) process.stdout.write(res.stdout);
  if (res.stderr) process.stderr.write(res.stderr);
  const elapsedMs = Date.now() - started;
  if (res.error) {
    throw new Error(`cmd_error step=${label} elapsedMs=${elapsedMs} message=${res.error.message}`);
  }
  if (res.signal) {
    throw new Error(`cmd_killed step=${label} elapsedMs=${elapsedMs} signal=${res.signal}`);
  }
  if (res.status !== 0) {
    throw new Error(`cmd_failed step=${label} elapsedMs=${elapsedMs} exitCode=${res.status}`);
  }
  console.log(`[artifacts] ok step=${label} elapsedMs=${elapsedMs}`);
};

const waitForFiles = async (label, files, timeoutMs) => {
  const started = Date.now();
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  while (Date.now() - started < timeoutMs) {
    if (files.every((p) => existsSync(p))) {
      console.log(`[artifacts] ok step=${label} elapsedMs=${Date.now() - started}`);
      return;
    }
    await sleep(250);
  }
  const missing = files.filter((p) => !existsSync(p));
  throw new Error(
    `timeout step=${label} elapsedMs=${Date.now() - started} missing=${missing.join(",")}`
  );
};

const runAndKillIfNeeded = async (label, cmd, args, cwd, options = {}) => {
  const started = Date.now();
  const timeoutMs = typeof options.timeoutMs === "number" ? options.timeoutMs : 30 * 60 * 1000;
  console.log(`\n[artifacts] step=${label}`);
  console.log(`[artifacts] cwd=${cwd}`);
  console.log(`[artifacts] cmd=${cmd} ${args.join(" ")}`);

  // Use spawn() so we can kill the process if it "finishes work" but never exits
  // (observed with circom2 WASM runtime on Windows).
  const child = spawn(cmd, args, {
    cwd,
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
    shell: false
  });
  child.stdout?.on("data", (d) => process.stdout.write(d));
  child.stderr?.on("data", (d) => process.stderr.write(d));

  let exited = false;
  let exitCode = null;
  let exitSignal = null;
  child.on("exit", (code, signal) => {
    exited = true;
    exitCode = code;
    exitSignal = signal;
  });

  // If the process doesn't exit within timeout, callers can decide to kill it.
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const deadline = Date.now() + timeoutMs;
  while (!exited && Date.now() < deadline) {
    await sleep(250);
  }

  const elapsedMs = Date.now() - started;
  if (!exited) {
    try {
      child.kill("SIGKILL");
    } catch {
      // ignore
    }
    throw new Error(`cmd_timeout_killed step=${label} elapsedMs=${elapsedMs}`);
  }
  if (exitSignal) {
    throw new Error(`cmd_killed step=${label} elapsedMs=${elapsedMs} signal=${exitSignal}`);
  }
  if (exitCode !== 0) {
    throw new Error(`cmd_failed step=${label} elapsedMs=${elapsedMs} exitCode=${exitCode}`);
  }
  console.log(`[artifacts] ok step=${label} elapsedMs=${elapsedMs}`);
};

const main = async () => {
  await mkdir(outDir, { recursive: true });

  // Prefer calling our wrapper to force clean exit on Windows. The upstream
  // `circom2` WASM CLI can finish compiling but keep the Node process alive due
  // to lingering WASI handles, which then trips timeouts.
  const circom2Wrapper = path.join(pkgDir, "src", "artifacts", "circom2-wrapper.cjs");
  const snarkjsMain = require.resolve("snarkjs");
  const snarkjsCli = path.join(path.dirname(snarkjsMain), "..", "cli.js");

  const circuitFile = "age_gte_v1.circom";
  const wasm = path.join(outDir, "age_gte_v1.wasm");
  const r1cs = path.join(outDir, "age_gte_v1.r1cs");
  const sym = path.join(outDir, "age_gte_v1.sym");
  const wasmEmitted = path.join(outDir, "age_gte_v1_js", "age_gte_v1.wasm");

  // Compile circuit (use -l to allow includes from node_modules/)
  // First, start the compile and wait for expected output files. If circom2
  // keeps the process alive after writing outputs (Windows), we'll kill it and continue.
  // IMPORTANT: clear previous outputs so our "waitForFiles" doesn't instantly succeed
  // by seeing stale files from a prior build (which would then copy the wrong WASM).
  await rm(path.join(outDir, "age_gte_v1_js"), { recursive: true, force: true });
  await rm(r1cs, { force: true });
  await rm(sym, { force: true });
  await rm(wasm, { force: true });

  const compileTimeoutMs = 20 * 60 * 1000;
  const compileCmd = process.execPath;
  const compileArgs = [
    circom2Wrapper,
    circuitFile,
    "--r1cs",
    "--wasm",
    "--sym",
    "--output",
    outDir,
    "-l",
    path.join(pkgDir, "node_modules")
  ];
  const compileChild = spawn(compileCmd, compileArgs, {
    cwd: circuitsDir,
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
    shell: false
  });
  compileChild.stdout?.on("data", (d) => process.stdout.write(d));
  compileChild.stderr?.on("data", (d) => process.stderr.write(d));

  await waitForFiles("circom.outputs", [r1cs, sym, wasmEmitted], compileTimeoutMs);
  console.log("[artifacts] after=circom.outputs");

  // Give circom a short chance to exit cleanly, then kill if still alive.
  const graceMs = 10_000;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  let exited = false;
  let exitCode = 0;
  compileChild.on("exit", (code) => {
    exited = true;
    exitCode = typeof code === "number" ? code : 0;
  });
  const graceDeadline = Date.now() + graceMs;
  while (!exited && Date.now() < graceDeadline) {
    await sleep(200);
  }
  if (!exited) {
    console.log("[artifacts] circom.compile did not exit; killing child");
    try {
      compileChild.kill("SIGKILL");
    } catch {
      // ignore
    }
  } else if (exitCode !== 0) {
    throw new Error(`cmd_failed step=circom.compile exitCode=${exitCode}`);
  }

  console.log("[artifacts] after=circom.compile");
  // circom emits wasm under `<circuit>_js/`; normalize to a stable path for the registry.
  console.log("[artifacts] read wasm emitted", wasmEmitted);
  const wasmBytes = await readFile(wasmEmitted);
  console.log("[artifacts] write wasm", wasm);
  await writeFile(wasm, wasmBytes);
  console.log("[artifacts] after=wasm.copy");

  // Minimal local setup (NOT a public ceremony). See SECURITY.md for guidance.
  // We use `beacon` commands to keep this non-interactive/reproducible for CI and contributors.
  const beaconHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  const ptau0 = path.join(outDir, "pot12_0000.ptau");
  const ptauBeacon = path.join(outDir, "pot12_beacon.ptau");
  const ptau = path.join(outDir, "pot12_final.ptau");
  const zkey0 = path.join(outDir, "age_gte_v1_0000.zkey");
  const zkey = path.join(outDir, "age_gte_v1.zkey");
  const vk = path.join(outDir, "age_gte_v1.verification_key.json");

  if (!(await readFile(ptau).catch(() => null))) {
    run(
      "snarkjs.powersoftau.new",
      process.execPath,
      [snarkjsCli, "powersoftau", "new", "bn128", "12", ptau0, "-v"],
      pkgDir
    );
    run(
      "snarkjs.powersoftau.beacon",
      process.execPath,
      [snarkjsCli, "powersoftau", "beacon", ptau0, ptauBeacon, beaconHash, "10"],
      pkgDir
    );
    run(
      "snarkjs.powersoftau.prepare",
      process.execPath,
      [snarkjsCli, "powersoftau", "prepare", "phase2", ptauBeacon, ptau, "-v"],
      pkgDir
    );
  }

  run(
    "snarkjs.groth16.setup",
    process.execPath,
    [snarkjsCli, "groth16", "setup", r1cs, ptau, zkey0],
    pkgDir
  );
  run(
    "snarkjs.zkey.beacon",
    process.execPath,
    [snarkjsCli, "zkey", "beacon", zkey0, zkey, beaconHash, "10"],
    pkgDir
  );
  run(
    "snarkjs.zkey.export_vkey",
    process.execPath,
    [snarkjsCli, "zkey", "export", "verificationkey", zkey, vk],
    pkgDir
  );

  // Emit a small manifest for the registry authoring step.
  const manifest = {
    wasm: {
      path: path.relative(repoRoot, wasm).replaceAll("\\", "/"),
      sha256_hex: await sha256Hex(wasm)
    },
    zkey: {
      path: path.relative(repoRoot, zkey).replaceAll("\\", "/"),
      sha256_hex: await sha256Hex(zkey)
    },
    vk: { path: path.relative(repoRoot, vk).replaceAll("\\", "/"), sha256_hex: await sha256Hex(vk) }
  };
  await writeFile(
    path.join(outDir, "manifest.json"),
    JSON.stringify(manifest, null, 2) + "\n",
    "utf8"
  );
  console.log("wrote manifest.json", manifest);
};

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
