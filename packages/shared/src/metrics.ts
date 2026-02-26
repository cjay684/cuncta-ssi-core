export type MetricLabels = Record<string, string | number | boolean>;

type MetricType = "counter" | "gauge";

type MetricEntry = {
  name: string;
  labels: MetricLabels;
  value: number;
  type: MetricType;
};

const normalizeLabels = (labels: MetricLabels) =>
  Object.entries(labels)
    .map(([key, value]) => [key, String(value)] as const)
    .sort((a, b) => a[0].localeCompare(b[0]));

const labelsKey = (labels: MetricLabels) => JSON.stringify(normalizeLabels(labels));

const formatLabels = (labels: MetricLabels) => {
  const entries = normalizeLabels(labels);
  if (!entries.length) return "";
  const formatted = entries.map(([key, value]) => `${key}="${value.replace(/"/g, '\\"')}"`);
  return `{${formatted.join(",")}}`;
};

export const createMetricsRegistry = (baseLabels: MetricLabels = {}) => {
  const entries = new Map<string, MetricEntry>();

  const record = (name: string, labels: MetricLabels, type: MetricType, value: number) => {
    const merged = { ...baseLabels, ...labels };
    const key = `${name}:${labelsKey(merged)}`;
    const existing = entries.get(key);
    if (existing) {
      existing.value = value;
      return;
    }
    entries.set(key, { name, labels: merged, value, type });
  };

  const incCounter = (name: string, labels: MetricLabels = {}, delta = 1) => {
    const merged = { ...baseLabels, ...labels };
    const key = `${name}:${labelsKey(merged)}`;
    const existing = entries.get(key);
    if (existing) {
      existing.value += delta;
      return;
    }
    entries.set(key, { name, labels: merged, value: delta, type: "counter" });
  };

  const setGauge = (name: string, labels: MetricLabels = {}, value: number) => {
    record(name, labels, "gauge", value);
  };

  const render = () => {
    const lines: string[] = [];
    const seenTypes = new Map<string, MetricType>();
    for (const entry of entries.values()) {
      const type = seenTypes.get(entry.name);
      if (!type) {
        lines.push(`# TYPE ${entry.name} ${entry.type}`);
        seenTypes.set(entry.name, entry.type);
      }
      lines.push(`${entry.name}${formatLabels(entry.labels)} ${entry.value}`);
    }
    return lines.join("\n") + "\n";
  };

  return { incCounter, setGauge, render };
};
