import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";

export const ensureDir = async (dir: string) => {
  await mkdir(dir, { recursive: true });
};

export const readJson = async <T>(filePath: string, fallback: T): Promise<T> => {
  try {
    const content = await readFile(filePath, "utf8");
    return JSON.parse(content) as T;
  } catch {
    return fallback;
  }
};

export const writeJson = async (filePath: string, data: unknown) => {
  await ensureDir(path.dirname(filePath));
  await writeFile(filePath, JSON.stringify(data, null, 2), "utf8");
};
