import { z } from "zod";

// Self-funded onboarding only (legacy mode removed).
export const OnboardingStrategySchema = z.enum(["user_pays"]);
export type OnboardingStrategy = z.infer<typeof OnboardingStrategySchema>;

export const parseOnboardingStrategyList = (value?: string) => {
  if (!value) return [];
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry): entry is OnboardingStrategy => entry === "user_pays");
};
