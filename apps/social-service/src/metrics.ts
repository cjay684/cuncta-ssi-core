import { createMetricsRegistry } from "@cuncta/shared";

export const metrics = createMetricsRegistry({ service: "social-service" });

for (const action of ["profile_create", "post", "reply", "follow", "report"]) {
  metrics.incCounter("social_action_attempt_total", { action }, 0);
  metrics.incCounter("social_action_allowed_total", { action }, 0);
  metrics.incCounter("social_action_denied_total", { action }, 0);
  metrics.incCounter("social_action_completed_total", { action }, 0);
}

metrics.incCounter("social_flow_feed_requests_total", {}, 0);
metrics.incCounter("social_explain_requests_total", {}, 0);
for (const mode of ["verified_only", "trusted_creator", "space_members", "safety_strict"]) {
  metrics.incCounter("social_trust_lens_usage_total", { mode }, 0);
}
metrics.incCounter("social_space_flow_requests_total", {}, 0);
for (const mode of ["verified_only", "trusted_creator", "space_members", "safety_strict"]) {
  metrics.incCounter("social_space_trust_lens_usage_total", { mode }, 0);
}
metrics.incCounter("social_space_governance_requests_total", {}, 0);
metrics.incCounter("social_space_moderation_audit_requests_total", {}, 0);
metrics.incCounter("social_space_analytics_requests_total", {}, 0);
