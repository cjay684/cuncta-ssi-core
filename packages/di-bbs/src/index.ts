import {
  blsSign,
  blsVerify,
  blsCreateProof,
  blsVerifyProof,
  generateBls12381G2KeyPair
} from "@mattrglobal/bbs-signatures";

export type DiBbsKeyPair = {
  publicKey: Uint8Array; // 96 bytes
  secretKey: Uint8Array; // 32 bytes
};

export type DiBbsCredential = {
  type: "VerifiableCredential";
  format: "di+bbs";
  vct: string;
  issuer: string;
  issuanceDate: string;
  credentialSubject: Record<string, unknown>;
  proof: {
    type: "DataIntegrityProof";
    cryptosuite: "bbs-2023";
    created: string;
    proofPurpose: "assertionMethod";
    verificationMethod: string;
    proofValueB64u: string;
    // Commit to the message mapping so verification is deterministic.
    messageCount: number;
    messageSchema: "cuncta.di.bbs.messages.v1";
  };
};

export type DiBbsDerivedPresentation = {
  type: "VerifiablePresentation";
  format: "di+bbs";
  vct: string;
  issuer: string;
  revealed: Record<string, unknown>;
  proof: {
    type: "DataIntegrityProof";
    cryptosuite: "bbs-2023";
    created: string;
    proofPurpose: "authentication";
    verificationMethod: string;
    proofValueB64u: string;
    revealedPaths: string[];
    messageSchema: "cuncta.di.bbs.messages.v1";
  };
};

const utf8 = (value: string) => new TextEncoder().encode(value);

const toBase64Url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const fromBase64Url = (value: string) => Uint8Array.from(Buffer.from(value, "base64url"));

const isRecord = (value: unknown): value is Record<string, unknown> =>
  Boolean(value) && typeof value === "object" && !Array.isArray(value);

const canonicalizeScalar = (value: unknown): string => {
  if (value === null) return "null";
  if (value === undefined) return "undefined";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" || typeof value === "boolean") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalizeScalar).join(",")}]`;
  if (isRecord(value)) {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalizeScalar(value[k])}`).join(",")}}`;
  }
  return JSON.stringify(String(value));
};

const flattenClaims = (
  claims: Record<string, unknown>,
  prefix = ""
): Array<{ path: string; value: unknown }> => {
  const out: Array<{ path: string; value: unknown }> = [];
  const keys = Object.keys(claims).sort();
  for (const key of keys) {
    const nextPath = prefix ? `${prefix}.${key}` : key;
    const value = claims[key];
    if (isRecord(value)) {
      out.push(...flattenClaims(value, nextPath));
    } else {
      out.push({ path: nextPath, value });
    }
  }
  return out;
};

// Deterministic message mapping:
// - VC metadata fields first, then credentialSubject flattened by path.
export const buildDiBbsMessagesV1 = (input: {
  issuer: string;
  vct: string;
  subject: Record<string, unknown>;
}) => {
  const pairs: Array<{ path: string; value: unknown }> = [
    { path: "issuer", value: input.issuer },
    { path: "vct", value: input.vct }
  ];
  pairs.push(...flattenClaims(input.subject, "credentialSubject"));
  return pairs.map((p) => utf8(`${p.path}=${canonicalizeScalar(p.value)}`));
};

export const generateDiBbsKeyPair = async (): Promise<DiBbsKeyPair> => {
  const kp = await generateBls12381G2KeyPair();
  return { publicKey: kp.publicKey, secretKey: kp.secretKey };
};

export const issueDiBbsCredential = async (input: {
  issuer: string;
  verificationMethod: string;
  vct: string;
  subjectClaims: Record<string, unknown>;
  keyPair: DiBbsKeyPair;
}): Promise<DiBbsCredential> => {
  const issuanceDate = new Date().toISOString();
  const created = issuanceDate;
  const messages = buildDiBbsMessagesV1({
    issuer: input.issuer,
    vct: input.vct,
    subject: input.subjectClaims
  });
  const signature = await blsSign({
    keyPair: { publicKey: input.keyPair.publicKey, secretKey: input.keyPair.secretKey },
    messages
  });
  const proofValueB64u = toBase64Url(signature);
  return {
    type: "VerifiableCredential",
    format: "di+bbs",
    vct: input.vct,
    issuer: input.issuer,
    issuanceDate,
    credentialSubject: input.subjectClaims,
    proof: {
      type: "DataIntegrityProof",
      cryptosuite: "bbs-2023",
      created,
      proofPurpose: "assertionMethod",
      verificationMethod: input.verificationMethod,
      proofValueB64u,
      messageCount: messages.length,
      messageSchema: "cuncta.di.bbs.messages.v1"
    }
  };
};

export const verifyDiBbsCredential = async (input: {
  credential: DiBbsCredential;
  publicKey: Uint8Array;
}) => {
  const messages = buildDiBbsMessagesV1({
    issuer: input.credential.issuer,
    vct: input.credential.vct,
    subject: input.credential.credentialSubject
  });
  const signature = fromBase64Url(input.credential.proof.proofValueB64u);
  const ok = await blsVerify({
    publicKey: input.publicKey,
    messages,
    signature
  });
  return { ok };
};

export const deriveDiBbsPresentation = async (input: {
  credential: DiBbsCredential;
  publicKey: Uint8Array;
  revealPaths: string[];
  nonce: Uint8Array; // proof nonce for unlinkability + request binding wrapper
}) => {
  const subject = input.credential.credentialSubject;
  const allPairs = flattenClaims(subject, "credentialSubject");
  const revealSet = new Set(input.revealPaths.map(String));
  const revealed: Record<string, unknown> = {};
  for (const pair of allPairs) {
    const claimPath = pair.path.replace(/^credentialSubject\./, "");
    if (!revealSet.has(claimPath)) continue;
    // Set nested structure in `revealed` for convenience.
    const parts = claimPath.split(".");
    let current = revealed;
    for (let i = 0; i < parts.length - 1; i += 1) {
      const part = parts[i]!;
      const next = current[part];
      if (!next || typeof next !== "object" || Array.isArray(next)) {
        current[part] = {};
      }
      current = current[part] as Record<string, unknown>;
    }
    current[parts[parts.length - 1]!] = pair.value;
  }

  const messages = buildDiBbsMessagesV1({
    issuer: input.credential.issuer,
    vct: input.credential.vct,
    subject: input.credential.credentialSubject
  });
  const signature = fromBase64Url(input.credential.proof.proofValueB64u);

  // Map reveal paths to message indices.
  const indices: number[] = [];
  // issuer + vct are always implicitly revealed (metadata; not personal data).
  indices.push(0, 1);
  for (const [idx, msg] of messages.entries()) {
    if (idx < 2) continue;
    const text = Buffer.from(msg).toString("utf8");
    const key = text.split("=", 1)[0] ?? "";
    // key is "credentialSubject.<path>"
    const claim = key.replace(/^credentialSubject\./, "");
    if (revealSet.has(claim)) {
      indices.push(idx);
    }
  }
  const revealedSorted = Array.from(new Set(indices)).sort((a, b) => a - b);
  const proofBytes = await blsCreateProof({
    signature,
    publicKey: input.publicKey,
    messages,
    nonce: input.nonce,
    revealed: revealedSorted
  });
  return {
    type: "VerifiablePresentation",
    format: "di+bbs",
    vct: input.credential.vct,
    issuer: input.credential.issuer,
    revealed,
    proof: {
      type: "DataIntegrityProof",
      cryptosuite: "bbs-2023",
      created: new Date().toISOString(),
      proofPurpose: "authentication",
      verificationMethod: input.credential.proof.verificationMethod,
      proofValueB64u: toBase64Url(proofBytes),
      revealedPaths: input.revealPaths,
      messageSchema: "cuncta.di.bbs.messages.v1"
    }
  } satisfies DiBbsDerivedPresentation as DiBbsDerivedPresentation;
};

export const verifyDiBbsPresentation = async (input: {
  presentation: DiBbsDerivedPresentation;
  credentialSubjectAll: Record<string, unknown>;
  issuer: string;
  vct: string;
  publicKey: Uint8Array;
  nonce: Uint8Array;
}) => {
  // The verifier must verify the proof over the original message set. Since this is
  // a derived proof, the holder supplies only revealed claims; we need the original
  // subject claims (or an issuer-issued credential). In this platform we attach the
  // original DI VC in the OID4VP wrapper to avoid server-side storage.
  const messagesAll = buildDiBbsMessagesV1({
    issuer: input.issuer,
    vct: input.vct,
    subject: input.credentialSubjectAll
  });

  const proof = fromBase64Url(input.presentation.proof.proofValueB64u);

  // Compute revealed message bytes subset matching disclosed fields.
  const revealSet = new Set(input.presentation.proof.revealedPaths.map(String));
  const revealedMessages: Uint8Array[] = [];
  // issuer + vct are always revealed
  revealedMessages.push(messagesAll[0]!, messagesAll[1]!);
  for (const msg of messagesAll.slice(2)) {
    const text = Buffer.from(msg).toString("utf8");
    const key = text.split("=", 1)[0] ?? "";
    const claim = key.replace(/^credentialSubject\./, "");
    if (revealSet.has(claim)) {
      revealedMessages.push(msg);
    }
  }

  const ok = await blsVerifyProof({
    proof,
    publicKey: input.publicKey,
    messages: revealedMessages,
    nonce: input.nonce
  });
  return { ok };
};
