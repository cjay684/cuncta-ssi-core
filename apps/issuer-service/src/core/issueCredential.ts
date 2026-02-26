import { issueCredential, issueDiBbsCredentialWithStatus } from "../issuer/issuance.js";

export type IssueCredentialCoreInput = {
  subjectDid: string;
  vct: string;
  claims: Record<string, unknown>;
  format?: "dc+sd-jwt" | "di+bbs";
};

// Phase 3: single issuance brain shared across protocol faces.
export const issueCredentialCore = async (input: IssueCredentialCoreInput) => {
  if (input.format === "di+bbs") {
    return issueDiBbsCredentialWithStatus({
      subjectDid: input.subjectDid,
      vct: input.vct,
      claims: input.claims
    });
  }
  return issueCredential({ subjectDid: input.subjectDid, vct: input.vct, claims: input.claims });
};

