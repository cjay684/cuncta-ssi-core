export type PrivateLaneIssueInput = {
  vct: string;
  claims: Record<string, unknown>;
};

export type PrivateLaneVerifyInput = {
  presentation: string;
};

export type PrivateLaneEngine = {
  issue: (input: PrivateLaneIssueInput) => Promise<never>;
  verify: (input: PrivateLaneVerifyInput) => Promise<never>;
};

export const createPrivateLaneEngine = (): PrivateLaneEngine => ({
  issue: async () => {
    throw new Error("private_lane_not_implemented");
  },
  verify: async () => {
    throw new Error("private_lane_not_implemented");
  }
});
