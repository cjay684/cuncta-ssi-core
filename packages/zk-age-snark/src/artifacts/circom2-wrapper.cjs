#!/usr/bin/env node
/**
 * circom2 wrapper for Windows reliability.
 *
 * The upstream `circom2` npm CLI runs Circom-in-WASM (wasmer/wasi). On Windows it can
 * finish compilation (and write output files) but keep the Node process alive due to
 * lingering handles in the WASI runtime. That breaks build scripts that rely on the
 * process exiting.
 *
 * This wrapper mirrors `circom2/cli.js`, but forces an explicit `process.exit(0)`
 * after `execute()` completes.
 */
const { CircomRunner, bindings } = require("circom2");
const fs = require("node:fs");
const path = require("node:path");

function preopensFull() {
  const preopens = {};
  let cwd = process.cwd();
  while (true) {
    const seg = path.relative(process.cwd(), cwd) || ".";
    preopens[seg] = seg;
    const next = path.dirname(cwd);
    if (next === cwd) break;
    cwd = next;
  }
  return preopens;
}

async function main() {
  const args = process.argv
    .slice(2)
    .map((k) => (k.startsWith("-") ? k : path.relative(process.cwd(), k)));
  if (args.length === 0) args.push("--help");

  const circom = new CircomRunner({
    args,
    env: process.env,
    preopens: preopensFull(),
    bindings: {
      ...bindings,
      exit(code) {
        process.exit(code);
      },
      kill(signal) {
        process.kill(process.pid, signal);
      },
      fs
    }
  });

  const wasmBytes = fs.readFileSync(require.resolve("circom2/circom.wasm"));
  await circom.execute(wasmBytes);

  // Force an exit even if WASI runtime kept handles open.
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
