import { SignJWT, jwtVerify, importJWK, JWK } from "jose";
import { createHash, randomBytes } from "node:crypto";

export type SdJwtPayload = Record<string, unknown>;

export type IssueSdJwtVcOptions = {
  issuerJwk: JWK;
  payload: SdJwtPayload;
  selectiveDisclosure: string[];
  typMode: "strict" | "legacy";
};

export type PresentSdJwtVcOptions = {
  sdJwt: string;
  disclose: string[];
};

export type VerifySdJwtVcOptions = {
  token: string;
  jwks: { keys: JWK[] };
  allowLegacyTyp?: boolean;
};

export type VerifySdJwtVcResult = {
  payload: SdJwtPayload;
  claims: SdJwtPayload;
  warnings: string[];
  diagnostics: {
    disclosureCount: number;
    invalidDisclosures: string[];
  };
};

const sha256Base64Url = (value: string) => createHash("sha256").update(value).digest("base64url");

const encodeDisclosure = (value: unknown[]) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

const decodeDisclosure = (disclosure: string) =>
  JSON.parse(Buffer.from(disclosure, "base64url").toString("utf8")) as unknown[];

const getByPath = (obj: SdJwtPayload, path: string) => {
  const parts = path.split(".");
  let current: unknown = obj;
  for (const part of parts) {
    if (!current || typeof current !== "object") {
      return undefined;
    }
    const record = current as Record<string, unknown>;
    current = record[part];
  }
  return current;
};

const deleteByPath = (obj: SdJwtPayload, path: string) => {
  const parts = path.split(".");
  if (parts.length === 1) {
    delete obj[parts[0] as keyof SdJwtPayload];
    return;
  }
  const last = parts.pop()!;
  let current: unknown = obj;
  for (const part of parts) {
    if (!current || typeof current !== "object") {
      return;
    }
    const record = current as Record<string, unknown>;
    current = record[part];
  }
  if (current && typeof current === "object") {
    const record = current as Record<string, unknown>;
    delete record[last];
  }
};

export async function issueSdJwtVc(options: IssueSdJwtVcOptions): Promise<string> {
  const alg = options.issuerJwk.alg ?? "EdDSA";
  const protectedHeader = {
    alg,
    typ: options.typMode === "legacy" ? "vc+sd-jwt" : "dc+sd-jwt",
    kid: options.issuerJwk.kid
  };

  const payload: SdJwtPayload = { ...options.payload };
  const disclosures: string[] = [];
  const digests: string[] = [];

  for (const path of options.selectiveDisclosure) {
    const value = getByPath(payload, path);
    if (value === undefined) {
      throw new Error(`disclosure_path_missing: ${path}`);
    }
    const claimName = path.split(".").at(-1) as string;
    const salt = randomBytes(16).toString("base64url");
    const disclosure = encodeDisclosure([salt, claimName, value]);
    const digest = sha256Base64Url(disclosure);
    disclosures.push(disclosure);
    digests.push(digest);
    deleteByPath(payload, path);
  }

  if (digests.length > 0) {
    payload._sd = digests;
    payload._sd_alg = "sha-256";
  }

  const key = await importJWK(options.issuerJwk, alg);
  const jwt = await new SignJWT(payload).setProtectedHeader(protectedHeader).sign(key);
  const segments = [jwt, ...disclosures];
  return `${segments.join("~")}~`;
}

export async function presentSdJwtVc(options: PresentSdJwtVcOptions): Promise<string> {
  const parts = options.sdJwt.split("~");
  const jwt = parts[0];
  const disclosures = parts.slice(1).filter((value) => value.length > 0);
  const selected = disclosures.filter((disclosure) => {
    const parsed = decodeDisclosure(disclosure);
    const name = parsed[1];
    return typeof name === "string" && options.disclose.includes(name);
  });
  const segments = [jwt, ...selected];
  return `${segments.join("~")}~`;
}

export async function verifySdJwtVc(options: VerifySdJwtVcOptions): Promise<VerifySdJwtVcResult> {
  const parts = options.token.split("~");
  const jwt = parts[0];
  const disclosures = parts.slice(1).filter((value) => value.length > 0);
  const header = JSON.parse(Buffer.from(jwt.split(".")[0] ?? "", "base64url").toString("utf8"));
  const jwk =
    options.jwks.keys.find((candidate) => candidate.kid && candidate.kid === header.kid) ??
    options.jwks.keys[0];
  if (!jwk) {
    throw new Error("jwks_missing");
  }
  const key = await importJWK(jwk, jwk.alg ?? "EdDSA");
  const { payload, protectedHeader } = await jwtVerify(jwt, key);
  const warnings: string[] = [];
  const typ = protectedHeader.typ ?? "";
  if (typ !== "dc+sd-jwt") {
    if (typ === "vc+sd-jwt" && options.allowLegacyTyp) {
      warnings.push("non_conformant_typ");
    } else {
      throw new Error("sd_jwt_typ_invalid");
    }
  }

  const sdDigests = Array.isArray((payload as SdJwtPayload)._sd)
    ? ((payload as SdJwtPayload)._sd as string[])
    : [];
  const validDigests = new Set(sdDigests);
  const invalidDisclosures: string[] = [];
  const disclosedClaims: SdJwtPayload = {};

  for (const disclosure of disclosures) {
    const digest = sha256Base64Url(disclosure);
    if (!validDigests.has(digest)) {
      invalidDisclosures.push(digest);
      continue;
    }
    const parsed = decodeDisclosure(disclosure);
    if (Array.isArray(parsed) && parsed.length >= 3) {
      const keyName = parsed[1];
      const value = parsed[2];
      if (typeof keyName === "string") {
        disclosedClaims[keyName] = value;
      }
    }
  }

  if (invalidDisclosures.length) {
    throw new Error("invalid_disclosure");
  }

  const cleanPayload: SdJwtPayload = { ...(payload as SdJwtPayload) };
  delete cleanPayload._sd;
  delete cleanPayload._sd_alg;

  return {
    payload: cleanPayload,
    claims: { ...cleanPayload, ...disclosedClaims },
    warnings,
    diagnostics: { disclosureCount: disclosures.length, invalidDisclosures }
  };
}
