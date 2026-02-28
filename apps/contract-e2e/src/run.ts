import dotenv from "dotenv";

dotenv.config({ path: "../../.env" });

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
  const gateway = requireEnv("APP_GATEWAY_BASE_URL").replace(/\/$/, "");

  await fetchJson(`${gateway}/healthz`);
  await fetchJson(`${gateway}/v1/requirements?action=identity.verify`);
  await fetchJson(`${gateway}/v1/capabilities`);

  console.log("PASS contract-e2e (ssi-only)");
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
