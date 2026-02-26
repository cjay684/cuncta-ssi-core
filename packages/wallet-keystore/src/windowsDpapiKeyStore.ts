import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { WalletStore, type WalletState } from "@cuncta/wallet";
import { getPublicKey, hashes, sign } from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { base58btc } from "multiformats/bases/base58";
import type { WalletKeyPurpose, WalletKeyStore, WalletPublicKeyMaterial } from "./types.js";

if (!hashes.sha512) {
  hashes.sha512 = sha512;
}

const toBase64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64");
const fromBase64 = (value: string) => new Uint8Array(Buffer.from(value, "base64"));
const toBase58Multibase = (publicKey: Uint8Array) => base58btc.encode(publicKey);

const requireWindows = () => {
  if (process.platform !== "win32") {
    throw new Error("dpapi_keystore_windows_only");
  }
};

const runPowerShellDpapi = (mode: "protect" | "unprotect", base64Input: string) => {
  requireWindows();
  // Use CryptProtectData/CryptUnprotectData via P/Invoke so we don't depend on .NET's ProtectedData type
  // being present in the runner's PowerShell/.NET build.
  const script = `
$code = @"
using System;
using System.Runtime.InteropServices;
public static class Dpapi {
  [StructLayout(LayoutKind.Sequential)]
  public struct DATA_BLOB {
    public int cbData;
    public IntPtr pbData;
  }

  [DllImport("Crypt32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  private static extern bool CryptProtectData(ref DATA_BLOB pDataIn, string szDataDescr, IntPtr pOptionalEntropy, IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, ref DATA_BLOB pDataOut);

  [DllImport("Crypt32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  private static extern bool CryptUnprotectData(ref DATA_BLOB pDataIn, IntPtr ppszDataDescr, IntPtr pOptionalEntropy, IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, ref DATA_BLOB pDataOut);

  [DllImport("Kernel32.dll", SetLastError=true)]
  private static extern IntPtr LocalFree(IntPtr hMem);

  private static DATA_BLOB ToBlob(byte[] data) {
    if (data == null) data = new byte[0];
    var blob = new DATA_BLOB();
    blob.cbData = data.Length;
    blob.pbData = Marshal.AllocHGlobal(data.Length);
    Marshal.Copy(data, 0, blob.pbData, data.Length);
    return blob;
  }

  private static byte[] FromBlob(DATA_BLOB blob) {
    if (blob.cbData <= 0 || blob.pbData == IntPtr.Zero) return new byte[0];
    var data = new byte[blob.cbData];
    Marshal.Copy(blob.pbData, data, 0, blob.cbData);
    return data;
  }

  public static byte[] ProtectCurrentUser(byte[] data) {
    var inBlob = ToBlob(data);
    var outBlob = new DATA_BLOB();
    try {
      const int CRYPTPROTECT_UI_FORBIDDEN = 0x1;
      if (!CryptProtectData(ref inBlob, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_UI_FORBIDDEN, ref outBlob)) {
        throw new Exception("CryptProtectData failed: " + Marshal.GetLastWin32Error());
      }
      var outBytes = FromBlob(outBlob);
      return outBytes;
    } finally {
      if (inBlob.pbData != IntPtr.Zero) Marshal.FreeHGlobal(inBlob.pbData);
      if (outBlob.pbData != IntPtr.Zero) LocalFree(outBlob.pbData);
    }
  }

  public static byte[] UnprotectCurrentUser(byte[] data) {
    var inBlob = ToBlob(data);
    var outBlob = new DATA_BLOB();
    try {
      const int CRYPTPROTECT_UI_FORBIDDEN = 0x1;
      if (!CryptUnprotectData(ref inBlob, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_UI_FORBIDDEN, ref outBlob)) {
        throw new Exception("CryptUnprotectData failed: " + Marshal.GetLastWin32Error());
      }
      var outBytes = FromBlob(outBlob);
      return outBytes;
    } finally {
      if (inBlob.pbData != IntPtr.Zero) Marshal.FreeHGlobal(inBlob.pbData);
      if (outBlob.pbData != IntPtr.Zero) LocalFree(outBlob.pbData);
    }
  }
}
"@

Add-Type -TypeDefinition $code -Language CSharp -ErrorAction Stop | Out-Null
$raw = [Console]::In.ReadToEnd().Trim()
$bytes = [Convert]::FromBase64String($raw)
${mode === "protect" ? "$out = [Dpapi]::ProtectCurrentUser($bytes)" : "$out = [Dpapi]::UnprotectCurrentUser($bytes)"}
[Console]::Out.Write([Convert]::ToBase64String($out))
`.trim();

  const res = spawnSync(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
    {
      input: `${base64Input}\n`,
      encoding: "utf8",
      maxBuffer: 1024 * 1024
    }
  );
  if (res.error) {
    throw new Error(`dpapi_${mode}_failed:${res.error.message}`);
  }
  if (res.status !== 0) {
    const stderr = (res.stderr ?? "").toString().trim();
    throw new Error(`dpapi_${mode}_failed:${stderr || "unknown"}`);
  }
  const out = (res.stdout ?? "").toString().trim();
  if (!out) {
    throw new Error(`dpapi_${mode}_failed:empty_output`);
  }
  return out;
};

const dpapiProtectBytes = (bytes: Uint8Array) => runPowerShellDpapi("protect", toBase64(bytes));
const dpapiUnprotectBytes = (ciphertextB64: string) => fromBase64(runPowerShellDpapi("unprotect", ciphertextB64));

const keyPath = (purpose: WalletKeyPurpose) => {
  if (purpose === "primary") return "ed25519_dpapi";
  if (purpose === "holder") return "holder_ed25519_dpapi";
  return "recovery_ed25519_dpapi";
};

type StoredDpapiKey = {
  privateKeyDpapiB64: string;
  publicKeyBase64: string;
  publicKeyMultibase: string;
  createdAt: string;
};

const readKey = (state: WalletState, purpose: WalletKeyPurpose): StoredDpapiKey | null => {
  const bucket = ((state as unknown as { keystore?: unknown }).keystore ?? {}) as Record<string, any>;
  const entry = bucket[keyPath(purpose)];
  if (!entry || typeof entry !== "object") return null;
  const cipher = String(entry.privateKeyDpapiB64 ?? "");
  const pub = String(entry.publicKeyBase64 ?? "");
  const mb = String(entry.publicKeyMultibase ?? "");
  if (!cipher || !pub) return null;
  return {
    privateKeyDpapiB64: cipher,
    publicKeyBase64: pub,
    publicKeyMultibase: mb || toBase58Multibase(fromBase64(pub)),
    createdAt: String(entry.createdAt ?? new Date().toISOString())
  };
};

const writeKey = (state: WalletState, purpose: WalletKeyPurpose, material: StoredDpapiKey) => {
  const root = state as unknown as { keystore?: Record<string, any> };
  const bucket = (root.keystore ?? {}) as Record<string, any>;
  bucket[keyPath(purpose)] = material;
  root.keystore = bucket;
};

export const createWindowsDpapiKeyStore = (input: {
  walletDir: string;
  filename?: string;
}): WalletKeyStore => {
  requireWindows();
  const store = new WalletStore({ walletDir: input.walletDir, filename: input.filename ?? "wallet-state.json" });

  const generate = async (purpose: WalletKeyPurpose) => {
    const privateKey = new Uint8Array(randomBytes(32));
    const publicKey = await getPublicKey(privateKey);
    const cipherB64 = dpapiProtectBytes(privateKey);
    return {
      stored: {
        privateKeyDpapiB64: cipherB64,
        publicKeyBase64: toBase64(publicKey),
        publicKeyMultibase: toBase58Multibase(publicKey),
        createdAt: new Date().toISOString()
      },
      public: {
        purpose,
        alg: "Ed25519" as const,
        publicKey,
        publicKeyMultibase: toBase58Multibase(publicKey)
      } satisfies WalletPublicKeyMaterial
    };
  };

  return {
    async ensureKey(purpose) {
      const state = await store.load();
      const existing = readKey(state, purpose);
      if (existing) {
        const publicKey = fromBase64(existing.publicKeyBase64);
        return {
          purpose,
          alg: "Ed25519",
          publicKey,
          publicKeyMultibase: existing.publicKeyMultibase || toBase58Multibase(publicKey)
        };
      }
      const created = await generate(purpose);
      writeKey(state, purpose, created.stored);
      await store.save(state);
      return created.public;
    },
    async loadKey(purpose) {
      const state = await store.load();
      const existing = readKey(state, purpose);
      if (!existing) return null;
      const publicKey = fromBase64(existing.publicKeyBase64);
      return {
        purpose,
        alg: "Ed25519",
        publicKey,
        publicKeyMultibase: existing.publicKeyMultibase || toBase58Multibase(publicKey)
      };
    },
    async sign(purpose, payload) {
      const state = await store.load();
      const existing = readKey(state, purpose);
      if (!existing) {
        throw new Error("wallet_key_missing");
      }
      const privateKey = dpapiUnprotectBytes(existing.privateKeyDpapiB64);
      return await sign(payload, privateKey);
    },
    async saveKeyMaterial(key) {
      if (key.alg !== "Ed25519") {
        throw new Error("wallet_key_alg_unsupported");
      }
      const state = await store.load();
      const cipherB64 = dpapiProtectBytes(key.privateKey);
      const stored: StoredDpapiKey = {
        privateKeyDpapiB64: cipherB64,
        publicKeyBase64: toBase64(key.publicKey),
        publicKeyMultibase: key.publicKeyMultibase ?? toBase58Multibase(key.publicKey),
        createdAt: new Date().toISOString()
      };
      writeKey(state, key.purpose, stored);
      await store.save(state);
    },
    async deleteKey(purpose) {
      const state = await store.load();
      const root = state as unknown as { keystore?: Record<string, any> };
      const bucket = (root.keystore ?? {}) as Record<string, any>;
      delete bucket[keyPath(purpose)];
      root.keystore = bucket;
      await store.save(state);
    }
  };
};

