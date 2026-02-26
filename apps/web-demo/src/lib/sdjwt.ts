import { decodeDisclosure } from "./crypto";

export const presentSdJwt = (sdJwt: string, disclose: string[]) => {
  const parts = sdJwt.split("~");
  const jwt = parts[0] ?? "";
  const disclosures = parts.slice(1).filter((value) => value.length > 0);
  const selected = disclosures.filter((disclosure) => {
    const parsed = decodeDisclosure(disclosure);
    const name = parsed[1];
    return typeof name === "string" && disclose.includes(name);
  });
  return `${[jwt, ...selected].join("~")}~`;
};
