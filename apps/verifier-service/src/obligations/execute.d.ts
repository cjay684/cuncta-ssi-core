type Obligation = {
  type: string;
  when?: "ON_ALLOW" | "ON_DENY" | "ALWAYS";
  [key: string]: unknown;
};
type ExecutionInput = {
  actionId: string;
  policyId: string;
  policyVersion: number;
  decision: "ALLOW" | "DENY";
  subjectDidHash: string;
  tokenHash: string;
  challengeHash: string;
  obligations: Obligation[];
};
type ExecutionResult = {
  executionId: string;
  obligations: Array<{
    type: string;
    status: "EXECUTED" | "SKIPPED" | "FAILED";
    error?: string;
  }>;
  blockedReason?: string;
};
export declare const executeObligations: (input: ExecutionInput) => Promise<ExecutionResult>;
export {};
