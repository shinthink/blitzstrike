/** Deterministic hash identification + fast common-password crack.
 *
 * When a finding dumps credential hashes, the agent must not leave "crack the
 * hashes" as a recommendation. This module identifies the hash type and tries a
 * built-in common-password list immediately (fast, offline, no external tools),
 * then returns the exact hashcat/john command for the full offline crack.
 */
import { createHash } from "node:crypto";

const COMMON_PASSWORDS = [
  "password", "123456", "12345678", "qwerty", "abc123", "admin", "admin123",
  "letmein", "welcome", "monkey", "dragon", "password1", "123456789", "111111",
  "iloveyou", "qwerty123", "root", "toor", "test", "guest", "Bonnie", "bonnie",
  "admin1234", "secret", "changeme", "Passw0rd", "P@ssw0rd", "qwertyuiop",
];

export function identifyHash(hash: string): string {
  if (/^\$2[aby]\$\d+\$/.test(hash)) return "bcrypt";
  if (/^\$1\$/.test(hash)) return "md5crypt";
  if (/^\$5\$/.test(hash)) return "sha256crypt";
  if (/^\$6\$/.test(hash)) return "sha512crypt";
  if (/^[a-f0-9]{32}$/i.test(hash)) return "md5";
  if (/^[a-f0-9]{40}$/i.test(hash)) return "sha1";
  if (/^[a-f0-9]{64}$/i.test(hash)) return "sha256";
  if (/^[a-f0-9]{128}$/i.test(hash)) return "sha512";
  if (/^[a-f0-9]{32}:[a-f0-9]{16,}$/i.test(hash)) return "ntlm";
  return "unknown";
}

const HASHCAT_MODE: Record<string, string> = {
  bcrypt: "3200", md5: "0", sha1: "100", sha256: "1400", sha512: "1700",
  md5crypt: "500", sha256crypt: "1800", sha512crypt: "1800", ntlm: "1000",
};

export async function crackHash(hash: string, extra: string[] = []): Promise<Record<string, unknown>> {
  const type = identifyHash(hash);
  const wordlist = [...new Set([...extra, ...COMMON_PASSWORDS])];
  const matches: string[] = [];

  for (const pw of wordlist) {
    try {
      if (type === "bcrypt") {
        const verify = (globalThis as Record<string, unknown>).Bun as { password?: { verifySync?: (p: string, h: string) => boolean } } | undefined;
        if (verify?.password?.verifySync?.(pw, hash)) matches.push(pw);
      } else {
        const algo = type === "md5" ? "md5" : type === "sha1" ? "sha1" : type === "sha256" ? "sha256" : "sha512";
        if (["md5", "sha1", "sha256", "sha512"].includes(type)) {
          if (createHash(algo).update(pw).digest("hex").toLowerCase() === hash.toLowerCase()) matches.push(pw);
        }
      }
    } catch {
      /* skip */
    }
  }

  const mode = HASHCAT_MODE[type];
  return {
    type,
    cracked: matches.length > 0,
    matches,
    recommendation: matches.length > 0
      ? `CRACKED — authenticate with '${matches[0]}' and continue the chain (login → dashboard → privileged actions).`
      : mode
        ? `Not in the built-in common list. Full crack: hashcat -m ${mode} -a 0 <hashes.txt> <wordlist> (bcrypt cost 12 needs GPU + time). Reuse the credential if it matches another account's hash (password reuse).`
        : "Unknown hash format — save it and identify manually before cracking.",
  };
}
