import { createMetricsRegistry } from "@cuncta/shared";

export const metrics = createMetricsRegistry({ service: "did-service" });

const registerDidResolutionMetrics = () => {
  metrics.incCounter("did_resolution_poll_total", {}, 0);
  metrics.incCounter("did_resolution_success_total", {}, 0);
  metrics.incCounter("did_resolution_timeout_total", {}, 0);
  metrics.incCounter("did_resolution_last_error_total", {}, 0);
  metrics.setGauge("did_resolution_last_elapsed_ms", {}, 0);
};

registerDidResolutionMetrics();
