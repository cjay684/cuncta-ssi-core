import { jwtVerify, JWTPayload } from "jose";

const textEncoder = new TextEncoder();

export const extractBearerToken = (authHeader?: string) => {
  if (!authHeader?.startsWith("Bearer ")) {
    return null;
  }
  return authHeader.slice(7);
};

export const verifyServiceJwt = async (
  token: string,
  options: {
    audience: string;
    secret: string;
    issuer?: string;
    subject?: string;
    requiredScopes?: string[];
  }
) => {
  const key = textEncoder.encode(options.secret);
  const { payload } = await jwtVerify(token, key, {
    audience: options.audience,
    issuer: options.issuer,
    subject: options.subject
  });
  if (!payload.exp || !payload.aud) {
    throw new Error("jwt_missing_required_claims");
  }
  if (options.requiredScopes && options.requiredScopes.length > 0) {
    const scopeValue = payload.scope;
    const tokenScopes = Array.isArray(scopeValue)
      ? scopeValue.map(String)
      : typeof scopeValue === "string"
        ? scopeValue.split(" ").filter(Boolean)
        : [];
    if (!options.requiredScopes.every((scope) => tokenScopes.includes(scope))) {
      throw new Error("jwt_missing_required_scope");
    }
  }
  return payload as JWTPayload;
};
