type LogMeta = Record<string, unknown>;
const SERVICE_NAME = "verifier-service";

const SENSITIVE_KEY =
  /secret|private|signature|payload|key|token|authorization|bearer|access[_-]?token|refresh[_-]?token|api[_-]?key|client[_-]?secret|secret[_-]?key|apikey/i;
const JWT_PATTERN = /eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g;

const redactString = (value: string) => {
  if (JWT_PATTERN.test(value)) {
    return value.replace(JWT_PATTERN, "[redacted]");
  }
  if (value.toLowerCase().startsWith("bearer ")) {
    return "Bearer [redacted]";
  }
  return value;
};

const redact = (value: unknown, depth = 0): unknown => {
  if (depth > 4) {
    return "[redacted]";
  }
  if (Array.isArray(value)) {
    return value.map((entry) => redact(entry, depth + 1));
  }
  if (value instanceof Error) {
    return { name: value.name, message: value.message };
  }
  if (typeof value === "string") {
    return redactString(value);
  }
  if (value && typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) {
      result[key] = SENSITIVE_KEY.test(key) ? "[redacted]" : redact(entry, depth + 1);
    }
    return result;
  }
  return value;
};

const write = (level: "info" | "warn" | "error", event: string, meta?: LogMeta) => {
  const safeMeta = meta ? redact(meta) : undefined;
  const payload = { level, service: SERVICE_NAME, event, ...(safeMeta ?? {}) };
  const line = JSON.stringify(payload);
  if (level === "error") {
    console.error(line);
    return;
  }
  if (level === "warn") {
    console.warn(line);
    return;
  }
  console.log(line);
};

export const log = {
  info: (message: string, meta?: LogMeta) => write("info", message, meta),
  warn: (message: string, meta?: LogMeta) => write("warn", message, meta),
  error: (message: string, meta?: LogMeta) => write("error", message, meta)
};
