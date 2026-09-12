/** Shared package version, read once from package.json. */
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

export const VERSION: string = (() => {
  try {
    const root = join(dirname(fileURLToPath(import.meta.url)), "..");
    return (JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { version?: string }).version ?? "unknown";
  } catch {
    return "unknown";
  }
})();
