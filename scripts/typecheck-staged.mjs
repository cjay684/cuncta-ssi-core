import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const repoRoot = path.resolve(process.cwd());
const packageJsonCache = new Map();

const findPackageDir = (filePath) => {
  let current = path.dirname(filePath);
  while (current.startsWith(repoRoot)) {
    if (packageJsonCache.has(current)) return packageJsonCache.get(current);
    const candidate = path.join(current, "package.json");
    if (fs.existsSync(candidate)) {
      packageJsonCache.set(current, current);
      return current;
    }
    packageJsonCache.set(current, null);
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return null;
};

const files = process.argv.slice(2).map((file) => path.resolve(file));
const packageDirs = new Set();

for (const file of files) {
  const pkgDir = findPackageDir(file);
  if (pkgDir) packageDirs.add(pkgDir);
}

if (packageDirs.size === 0) {
  process.exit(0);
}

for (const pkgDir of packageDirs) {
  const pkgPath = path.join(pkgDir, "package.json");
  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
  if (!pkg.scripts?.typecheck) continue;
  const result = spawnSync("pnpm", ["-C", pkgDir, "typecheck"], {
    stdio: "inherit",
    shell: true
  });
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}
