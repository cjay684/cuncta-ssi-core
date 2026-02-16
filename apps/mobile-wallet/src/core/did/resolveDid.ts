import { createGatewayClient } from "../gateway/client.js";

export const resolveDidWithGateway = async (input: {
  baseUrl: string;
  did: string;
  maxAttempts?: number;
  intervalMs?: number;
}) => {
  const client = createGatewayClient(input.baseUrl);
  const maxAttempts = input.maxAttempts ?? 60;
  const intervalMs = input.intervalMs ?? 4000;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const response = await client.resolveDid(input.did);
    if (response.didDocument && Object.keys(response.didDocument).length > 0) {
      return { attempts: attempt, didDocument: response.didDocument };
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new Error("did_resolution_timeout");
};
