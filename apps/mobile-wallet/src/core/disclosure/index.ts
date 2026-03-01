import { createHash } from "node:crypto";
import { presentSdJwtVc } from "@cuncta/sdjwt";

export type DisclosureOption = {
  id: string;
  label: string;
  path?: string;
  disclosure: string;
  sensitive?: boolean;
};

const sha256Base64Url = (value: string) => createHash("sha256").update(value).digest("base64url");

const decodeDisclosure = (disclosure: string) =>
  JSON.parse(Buffer.from(disclosure, "base64url").toString("utf8")) as unknown[];

const isSensitiveName = (name: string) =>
  /ssn|dob|birth|email|phone|address|name|passport|license/i.test(name);

const disclosureId = (disclosure: string, path?: string, label?: string) => {
  const suffix = path ?? label ?? "";
  return sha256Base64Url(`sdjwt-disclosure:${disclosure}:${suffix}`);
};

export const extractDisclosureOptions = (sdJwt: string): DisclosureOption[] => {
  const parts = sdJwt.split("~");
  const disclosures = parts.slice(1).filter((value) => value.length > 0);
  const options: DisclosureOption[] = [];
  for (const disclosure of disclosures) {
    try {
      const parsed = decodeDisclosure(disclosure);
      const name = parsed[1];
      if (typeof name !== "string") {
        continue;
      }
      options.push({
        id: disclosureId(disclosure, name, name),
        label: name,
        path: name,
        disclosure,
        sensitive: isSensitiveName(name)
      });
    } catch {
      continue;
    }
  }
  return options;
};

export const applyDisclosureSelection = (sdJwt: string, selectedIds: string[]) => {
  if (!selectedIds.length) {
    throw new Error("disclosure_selection_required");
  }
  const parts = sdJwt.split("~");
  const jwt = parts[0] ?? "";
  const options = extractDisclosureOptions(sdJwt);
  const selected = options
    .filter((opt) => selectedIds.includes(opt.id))
    .map((opt) => opt.disclosure);
  return `${[jwt, ...selected].join("~")}~`;
};

export const discloseAll = async (sdJwt: string) => {
  const options = extractDisclosureOptions(sdJwt);
  const names = options.map((opt) => opt.label);
  return presentSdJwtVc({ sdJwt, disclose: names });
};

export const deriveRequiredDisclosures = (input: {
  requirements: {
    requirements: Array<{
      vct?: string;
      disclosures?: string[];
      predicates?: Array<{ path?: string } & Record<string, unknown>>;
    }>;
  };
  options: DisclosureOption[];
  vct?: string;
}) => {
  const requirement =
    input.requirements.requirements.find((req) => req.vct && req.vct === input.vct) ??
    input.requirements.requirements[0];
  if (!requirement) {
    return [];
  }
  const requiredIds = new Set<string>();
  const requiredNames = new Set<string>(requirement.disclosures ?? []);
  for (const predicate of requirement.predicates ?? []) {
    if (predicate && typeof predicate.path === "string") {
      const path = predicate.path;
      const exact = input.options.filter((opt) => opt.path === path);
      if (exact.length) {
        exact.forEach((opt) => requiredIds.add(opt.id));
        continue;
      }
      const last = path.split(".").at(-1);
      if (!last) continue;
      const matches = input.options.filter((opt) => opt.label === last);
      if (matches.length === 1) {
        requiredIds.add(matches[0].id);
      }
    }
  }
  for (const name of requiredNames) {
    const matches = input.options.filter((opt) => opt.label === name || opt.path === name);
    if (matches.length === 1) {
      requiredIds.add(matches[0].id);
    }
  }
  return Array.from(requiredIds);
};
