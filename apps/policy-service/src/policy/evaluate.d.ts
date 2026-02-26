import { z } from "zod";
export declare const PredicateSchema: z.ZodObject<
  {
    path: z.ZodString;
    op: z.ZodEnum<{
      in: "in";
      eq: "eq";
      neq: "neq";
      gte: "gte";
      lte: "lte";
      exists: "exists";
    }>;
    value: z.ZodOptional<z.ZodUnknown>;
  },
  z.core.$strip
>;
export declare const IssuerRuleSchema: z.ZodObject<
  {
    mode: z.ZodEnum<{
      allowlist: "allowlist";
      env: "env";
    }>;
    allowed: z.ZodOptional<z.ZodArray<z.ZodString>>;
    env: z.ZodOptional<z.ZodString>;
  },
  z.core.$strip
>;
export declare const RequirementSchema: z.ZodObject<
  {
    vct: z.ZodString;
    issuer: z.ZodOptional<
      z.ZodObject<
        {
          mode: z.ZodEnum<{
            allowlist: "allowlist";
            env: "env";
          }>;
          allowed: z.ZodOptional<z.ZodArray<z.ZodString>>;
          env: z.ZodOptional<z.ZodString>;
        },
        z.core.$strip
      >
    >;
    disclosures: z.ZodDefault<z.ZodArray<z.ZodString>>;
    predicates: z.ZodDefault<
      z.ZodArray<
        z.ZodObject<
          {
            path: z.ZodString;
            op: z.ZodEnum<{
              in: "in";
              eq: "eq";
              neq: "neq";
              gte: "gte";
              lte: "lte";
              exists: "exists";
            }>;
            value: z.ZodOptional<z.ZodUnknown>;
          },
          z.core.$strip
        >
      >
    >;
    revocation: z.ZodOptional<
      z.ZodObject<
        {
          required: z.ZodBoolean;
        },
        z.core.$strip
      >
    >;
  },
  z.core.$strip
>;
export declare const PolicyLogicSchema: z.ZodObject<
  {
    binding: z.ZodOptional<
      z.ZodObject<
        {
          mode: z.ZodDefault<
            z.ZodEnum<{
              nonce: "nonce";
              "kb-jwt": "kb-jwt";
            }>
          >;
          require: z.ZodDefault<z.ZodBoolean>;
        },
        z.core.$strip
      >
    >;
    requirements: z.ZodDefault<
      z.ZodArray<
        z.ZodObject<
          {
            vct: z.ZodString;
            issuer: z.ZodOptional<
              z.ZodObject<
                {
                  mode: z.ZodEnum<{
                    allowlist: "allowlist";
                    env: "env";
                  }>;
                  allowed: z.ZodOptional<z.ZodArray<z.ZodString>>;
                  env: z.ZodOptional<z.ZodString>;
                },
                z.core.$strip
              >
            >;
            disclosures: z.ZodDefault<z.ZodArray<z.ZodString>>;
            predicates: z.ZodDefault<
              z.ZodArray<
                z.ZodObject<
                  {
                    path: z.ZodString;
                    op: z.ZodEnum<{
                      in: "in";
                      eq: "eq";
                      neq: "neq";
                      gte: "gte";
                      lte: "lte";
                      exists: "exists";
                    }>;
                    value: z.ZodOptional<z.ZodUnknown>;
                  },
                  z.core.$strip
                >
              >
            >;
            revocation: z.ZodOptional<
              z.ZodObject<
                {
                  required: z.ZodBoolean;
                },
                z.core.$strip
              >
            >;
          },
          z.core.$strip
        >
      >
    >;
    obligations: z.ZodDefault<
      z.ZodArray<
        z.ZodObject<
          {
            type: z.ZodString;
          },
          z.core.$loose
        >
      >
    >;
  },
  z.core.$strip
>;
export type PolicyLogic = z.infer<typeof PolicyLogicSchema>;
export type PolicyRecord = {
  policyId: string;
  actionId: string;
  version: number;
  enabled: boolean;
  logic: PolicyLogic;
};
export declare const getPolicyForAction: (actionId: string) => Promise<PolicyRecord | null>;
export declare const evaluate: (input: { action: string }) => Promise<{
  action: string;
  requirements: {
    vct: string;
    disclosures: string[];
    predicates: {
      path: string;
      op: "in" | "eq" | "neq" | "gte" | "lte" | "exists";
      value?: unknown;
    }[];
    issuer?:
      | {
          mode: "allowlist" | "env";
          allowed?: string[] | undefined;
          env?: string | undefined;
        }
      | undefined;
    revocation?:
      | {
          required: boolean;
        }
      | undefined;
  }[];
  obligations: {
    [x: string]: unknown;
    type: string;
  }[];
  binding:
    | {
        mode: "nonce" | "kb-jwt";
        require: boolean;
      }
    | undefined;
}>;
