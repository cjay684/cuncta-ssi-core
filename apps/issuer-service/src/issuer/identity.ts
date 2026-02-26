import { config } from "../config.js";
import { bootstrapIssuerDid } from "./bootstrapIssuerDid.js";
import { getIssuerJwks } from "./keyRing.js";

const isProduction = config.NODE_ENV === "production";
const issuerIdentity = config.ISSUER_DID
  ? { issuerDid: config.ISSUER_DID }
  : isProduction
    ? (() => {
        throw new Error("issuer_did_required");
      })()
    : await bootstrapIssuerDid();

export const ISSUER_DID = issuerIdentity.issuerDid;

export const getIssuerDid = async () => ISSUER_DID;
export const getIssuerDidForSubject = async (_subjectDid: string) => ISSUER_DID;
export const getIssuerJwksForVerifier = async () => getIssuerJwks();
