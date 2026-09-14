/** Git-history secret mining — recover secrets that were DELETED from the working
 *  tree but remain in `.git` history. Deletion only removes a file from HEAD; the
 *  blob stays reachable by every ancestor commit, so a "removed later" secret is
 *  still a live disclosure ("removed later != fixed").
 *
 *  Read-only: it only runs `git log` / `git show` (no mutation). Reuses the
 *  hardcoded_secret detector (SECRET_FIELDS + SECRET_FORMATS + entropy) from
 *  complex-bugs.ts on each recovered pre-deletion blob.
 */
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { detectComplexBugs } from "./complex-bugs.js";

export interface GitHistoryFinding {
  path: string;
  commit: string;
  commit_msg: string;
  severity: string;
  category: string;
  evidence: string;
  detail: string;
}

interface Deletion {
  commit: string;
  commit_msg: string;
  path: string;
}

/** Parse `git log --all --diff-filter=D --name-status` into (commit, path) deletions. */
function parseDeletions(output: string): Deletion[] {
  const out: Deletion[] = [];
  let commit = "";
  let msg = "";
  for (const line of output.split("\n")) {
    if (line.startsWith("__COMMIT__ ")) {
      const rest = line.slice("__COMMIT__ ".length);
      const sp = rest.indexOf(" ");
      commit = sp === -1 ? rest : rest.slice(0, sp);
      msg = sp === -1 ? "" : rest.slice(sp + 1);
    } else if (line.startsWith("D\t") || line.startsWith("D ")) {
      const path = line.slice(2).trim();
      if (path && commit) out.push({ commit, commit_msg: msg, path });
    }
  }
  return out;
}

/** Recover the blob exactly BEFORE a deletion commit (`<sha>^:<path>`). */
function blobBeforeDeletion(root: string, commit: string, path: string): string {
  return execFileSync("git", ["-C", root, "show", `${commit}^:${path}`], {
    encoding: "utf8",
    maxBuffer: 10 * 1024 * 1024,
  });
}

/** Scan a git repo's history for secrets in deleted files. */
export function scanGitHistory(root: string, opts?: { secretPattern?: string; limit?: number }): Record<string, unknown> {
  const limit = opts?.limit ?? 30;
  const findings: GitHistoryFinding[] = [];

  if (!existsSync(join(root, ".git"))) {
    return { root, is_git_repo: false, total: 0, findings: [], error: "not a git repository (no .git dir)" };
  }

  // Pickaxe mode: a specific secret token the caller wants traced through history.
  if (opts?.secretPattern) {
    try {
      const pick = execFileSync(
        "git", ["-C", root, "log", "-S", opts.secretPattern, "--all", "--format=__COMMIT__ %H %s"],
        { encoding: "utf8", maxBuffer: 5 * 1024 * 1024 },
      );
      const commits = pick.split("\n").filter(Boolean).map((l) => {
        const rest = l.startsWith("__COMMIT__ ") ? l.slice("__COMMIT__ ".length) : l;
        const sp = rest.indexOf(" ");
        return { hash: sp === -1 ? rest : rest.slice(0, sp), msg: sp === -1 ? "" : rest.slice(sp + 1) };
      });
      return {
        root, is_git_repo: true, mode: "pickaxe", pattern: opts.secretPattern,
        total: commits.length, commits,
        hint: "Commits where the pattern was added or removed — inspect each to recover the secret value.",
      };
    } catch (e) {
      return { root, is_git_repo: true, mode: "pickaxe", pattern: opts.secretPattern, total: 0, error: String(e) };
    }
  }

  try {
    const log = execFileSync(
      "git", ["-C", root, "log", "--all", "--diff-filter=D", "--name-status", "--format=__COMMIT__ %H %s", "--no-renames"],
      { encoding: "utf8", maxBuffer: 10 * 1024 * 1024 },
    );
    const deletions = parseDeletions(log);
    const seen = new Set<string>();
    let checked = 0;

    for (const d of deletions) {
      if (findings.length >= limit) break;
      const key = `${d.path}`;
      if (seen.has(key)) continue;
      seen.add(key);
      try {
        const blob = blobBeforeDeletion(root, d.commit, d.path);
        checked++;
        const hits = detectComplexBugs(blob, d.path).filter((f) => f.type === "hardcoded_secret");
        for (const h of hits) {
          findings.push({
            path: d.path,
            commit: d.commit,
            commit_msg: d.commit_msg,
            severity: h.severity,
            category: h.category,
            evidence: h.evidence,
            detail: `A ${h.category} was found in a file DELETED from HEAD but still present in git history (commit ${d.commit}). Removed-later is not fixed — anyone with the repo history can recover it.`,
          });
        }
      } catch {
        // blob not recoverable (binary, submodule, or renamed) — skip
      }
    }

    return {
      root, is_git_repo: true, mode: "deleted_files",
      deletion_commits: deletions.length, blobs_checked: checked,
      total: findings.length, findings,
      hint: "Secrets in deleted files remain in .git history. Rotate any recovered credential and rewrite/scrub history.",
    };
  } catch (e) {
    return { root, is_git_repo: true, mode: "deleted_files", total: 0, findings: [], error: String(e) };
  }
}
