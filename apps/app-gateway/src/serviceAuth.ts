import { SignJWT } from "jose";

const textEncoder = new TextEncoder();

export const createServiceJwt = async (input: {
  audience: string;
  secret: string;
  ttlSeconds: number;
  scope: string[] | string;
  issuer?: string;
  subject?: string;
}) => {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const key = textEncoder.encode(input.secret);
  return new SignJWT({
    aud: input.audience,
    scope: input.scope,
    iat: nowSeconds,
    exp: nowSeconds + input.ttlSeconds,
    iss: input.issuer ?? "app-gateway",
    sub: input.subject ?? "app-gateway"
  })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .sign(key);
};
