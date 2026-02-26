import { z } from "zod";

const capabilitiesSchema = z.object({
  selfFundedOnboarding: z.object({
    enabled: z.boolean(),
    maxFeeTinybars: z.number().int().positive().optional(),
    maxTxBytes: z.number().int().positive().optional(),
    requestTtlSeconds: z.number().int().positive().optional()
  }),
  network: z.enum(["testnet", "previewnet", "mainnet"]),
  requirements: z.object({ requireDeviceId: z.boolean() })
});

const userPaysRequestSchema = z.object({
  handoffToken: z.string().min(10),
  expiresAt: z.string(),
  network: z.enum(["testnet", "previewnet", "mainnet"]),
  topicId: z.string(),
  publicKeyMultibase: z.string()
});

const userPaysSubmitSchema = z.object({
  transactionId: z.string().optional(),
  status: z.string().optional(),
  requestId: z.string().optional()
});

const resolveSchema = z.object({
  didDocument: z.record(z.string(), z.unknown()).optional()
});

const requirementsSchema = z
  .object({
    action: z.string(),
    action_id: z.string().optional(),
    policyId: z.string().optional(),
    version: z.number().optional(),
    binding: z.object({ mode: z.string().optional(), require: z.boolean().optional() }).optional(),
    requirements: z.array(
      z
        .object({
          vct: z.string(),
          disclosures: z.array(z.string()).default([])
        })
        .passthrough()
    ),
    obligations: z.array(z.unknown()).default([]),
    challenge: z.object({
      nonce: z.string(),
      audience: z.string(),
      expires_at: z.string()
    })
  })
  .passthrough();

const verifyResponseSchema = z.object({
  decision: z.enum(["ALLOW", "DENY"]),
  message: z.string().optional(),
  requestId: z.string().optional()
});

export type GatewayClient = {
  getCapabilities(): Promise<z.infer<typeof capabilitiesSchema>>;
  userPaysDidCreateRequest(input: {
    network: "testnet" | "previewnet" | "mainnet";
    publicKeyMultibase: string;
    deviceId: string;
  }): Promise<z.infer<typeof userPaysRequestSchema>>;
  userPaysDidCreateSubmit(input: {
    handoffToken: string;
    signedTransactionB64u: string;
    deviceId: string;
  }): Promise<z.infer<typeof userPaysSubmitSchema>>;
  resolveDid(did: string): Promise<z.infer<typeof resolveSchema>>;
  getRequirements(input: {
    action: string;
    deviceId: string;
  }): Promise<z.infer<typeof requirementsSchema>>;
  verifyPresentation(input: {
    action: string;
    presentation: string;
    nonce: string;
    audience: string;
  }): Promise<z.infer<typeof verifyResponseSchema>>;
};

export const createGatewayClient = (baseUrl: string): GatewayClient => {
  const getJson = async (url: URL, init?: RequestInit) => {
    const response = await fetch(url, init);
    if (!response.ok) {
      const body = await response.text();
      throw new Error(`HTTP ${response.status}: ${body}`);
    }
    return response.json() as Promise<unknown>;
  };

  return {
    async getCapabilities() {
      const url = new URL("/v1/capabilities", baseUrl);
      const payload = await getJson(url, { method: "GET" });
      return capabilitiesSchema.parse(payload);
    },
    async userPaysDidCreateRequest(input) {
      const url = new URL("/v1/onboard/did/create/user-pays/request", baseUrl);
      const payload = await getJson(url, {
        method: "POST",
        headers: { "content-type": "application/json", "x-device-id": input.deviceId },
        body: JSON.stringify({
          network: input.network,
          publicKeyMultibase: input.publicKeyMultibase,
          options: { topicManagement: "shared", includeServiceEndpoints: true }
        })
      });
      return userPaysRequestSchema.parse(payload);
    },
    async userPaysDidCreateSubmit(input) {
      const url = new URL("/v1/onboard/did/create/user-pays/submit", baseUrl);
      const payload = await getJson(url, {
        method: "POST",
        headers: { "content-type": "application/json", "x-device-id": input.deviceId },
        body: JSON.stringify({
          handoffToken: input.handoffToken,
          signedTransactionB64u: input.signedTransactionB64u
        })
      });
      return userPaysSubmitSchema.parse(payload);
    },
    async resolveDid(did) {
      const url = new URL(`/v1/dids/resolve/${encodeURIComponent(did)}`, baseUrl);
      const payload = await getJson(url, { method: "GET" });
      return resolveSchema.parse(payload);
    },
    async getRequirements(input) {
      const url = new URL("/v1/requirements", baseUrl);
      url.searchParams.set("action", input.action);
      const payload = await getJson(url, {
        method: "GET",
        headers: { "x-device-id": input.deviceId }
      });
      return requirementsSchema.parse(payload);
    },
    async verifyPresentation(input) {
      const url = new URL("/v1/verify", baseUrl);
      url.searchParams.set("action", input.action);
      const payload = await getJson(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          presentation: input.presentation,
          nonce: input.nonce,
          audience: input.audience
        })
      });
      return verifyResponseSchema.parse(payload);
    }
  };
};
