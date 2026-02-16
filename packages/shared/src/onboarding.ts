import { z } from "zod";

export const OnboardingStrategySchema = z.enum(["sponsored", "user_pays"]);
export type OnboardingStrategy = z.infer<typeof OnboardingStrategySchema>;

export const parseOnboardingStrategyList = (value?: string) => {
  if (!value) return [];
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry): entry is OnboardingStrategy => entry === "sponsored" || entry === "user_pays");
};
