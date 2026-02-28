import dotenv from "dotenv";

dotenv.config({ path: "../../.env" });

const required = [
  "APP_GATEWAY_BASE_URL",
  "ISSUER_SERVICE_BASE_URL",
  "VERIFIER_SERVICE_BASE_URL",
  "DID_SERVICE_BASE_URL"
];

const requireEnv = (name: string) => {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`missing_required_env:${name}`);
  return value;
};

const fetchJson = async (url: string, init?: RequestInit) => {
  const res = await fetch(url, init);
  const text = await res.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  if (!res.ok) {
    throw new Error(`http_${res.status}:${url}:${typeof body === "string" ? body : JSON.stringify(body)}`);
  }
  return body;
};

const run = async () => {
  for (const name of required) requireEnv(name);
  const gateway = requireEnv("APP_GATEWAY_BASE_URL").replace(/\/$/, "");
  const issuer = requireEnv("ISSUER_SERVICE_BASE_URL").replace(/\/$/, "");
  const verifier = requireEnv("VERIFIER_SERVICE_BASE_URL").replace(/\/$/, "");
  const didService = requireEnv("DID_SERVICE_BASE_URL").replace(/\/$/, "");

  await fetchJson(`${gateway}/healthz`);
  await fetchJson(`${issuer}/healthz`);
  await fetchJson(`${verifier}/healthz`);
  await fetchJson(`${didService}/healthz`);

  await fetchJson(`${gateway}/v1/requirements?action=identity.verify`);
  await fetchJson(`${issuer}/.well-known/openid-credential-issuer`);

  console.log("PASS integration-tests (ssi-only)");
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
