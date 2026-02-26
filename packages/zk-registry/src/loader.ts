import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { ZkStatementDefinitionSchema, type ZkStatementDefinition } from "./schema.js";

const repoRoot = () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(here, "..", "..", "..");
};

export const zkRegistryDir = () => path.join(repoRoot(), "packages", "zk-registry");

export const sha256HexFile = async (absolutePath: string) => {
  const bytes = await readFile(absolutePath);
  return createHash("sha256").update(bytes).digest("hex");
};

const readJsonFile = async (absolutePath: string) => {
  const raw = await readFile(absolutePath, "utf8");
  return JSON.parse(raw) as unknown;
};

export type LoadedStatement = {
  definition: ZkStatementDefinition;
  // Absolute paths resolved from refs.
  provingKeyPath: string;
  verifyingKeyPath: string;
  wasmPath?: string;
  available: boolean;
};

export const loadZkStatementRegistry = async (): Promise<Map<string, LoadedStatement>> => {
  const base = zkRegistryDir();
  const statementsDir = path.join(base, "statements");
  const list = await readFile(path.join(statementsDir, "index.json"), "utf8").catch(() => "[]");
  const files = (JSON.parse(list) as unknown[]).map(String);

  const out = new Map<string, LoadedStatement>();
  for (const rel of files) {
    const statementPath = path.join(statementsDir, rel);
    const json = await readJsonFile(statementPath);
    const def = ZkStatementDefinitionSchema.parse(json);

    const provingKeyPath = path.join(repoRoot(), def.proving_key_ref.path);
    const verifyingKeyPath = path.join(repoRoot(), def.verifying_key_ref.path);
    const wasmPath = def.wasm_ref ? path.join(repoRoot(), def.wasm_ref.path) : undefined;

    const isStub =
      def.deprecated === true ||
      def.proving_key_ref.sha256_hex === "0".repeat(64) ||
      def.verifying_key_ref.sha256_hex === "0".repeat(64);
    if (!isStub) {
      const [pkHash, vkHash, wasmHash] = await Promise.all([
        sha256HexFile(provingKeyPath),
        sha256HexFile(verifyingKeyPath),
        wasmPath ? sha256HexFile(wasmPath) : Promise.resolve(null)
      ]);
      if (pkHash !== def.proving_key_ref.sha256_hex) {
        throw new Error(`zk_registry_hash_mismatch:proving_key:${def.statement_id}`);
      }
      if (vkHash !== def.verifying_key_ref.sha256_hex) {
        throw new Error(`zk_registry_hash_mismatch:verifying_key:${def.statement_id}`);
      }
      if (def.wasm_ref && wasmHash !== def.wasm_ref.sha256_hex) {
        throw new Error(`zk_registry_hash_mismatch:wasm:${def.statement_id}`);
      }
    }

    out.set(def.statement_id, {
      definition: def,
      provingKeyPath,
      verifyingKeyPath,
      wasmPath
      ,
      available: !isStub
    });
  }
  return out;
};

let cached: Map<string, LoadedStatement> | null = null;

export const getZkStatement = async (statementId: string) => {
  if (!cached) {
    cached = await loadZkStatementRegistry();
  }
  const entry = cached.get(statementId);
  if (!entry) {
    throw new Error("zk_statement_not_found");
  }
  return entry;
};

