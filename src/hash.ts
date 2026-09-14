/** Deterministic hash identification + offline password crack.
 *
 *  When a finding dumps credential hashes, the agent must not leave "crack the
 *  hashes" as a recommendation. This module identifies the hash type and tries a
 *  built-in common-password list immediately (fast, offline, no external tools),
 *  then streams any supplied/autodetected wordlist (rockyou, seclists, etc.),
 *  then returns the exact hashcat/john command for the full offline crack.
 */
import { createHash } from "node:crypto";
import { createReadStream, existsSync } from "node:fs";
import { createInterface } from "node:readline";

const COMMON_PASSWORDS = [
  "password", "123456", "12345678", "qwerty", "abc123", "admin", "admin123",
  "letmein", "welcome", "monkey", "dragon", "password1", "123456789", "111111",
  "iloveyou", "qwerty123", "root", "toor", "test", "guest", "Bonnie", "bonnie",
  "admin1234", "secret", "changeme", "Passw0rd", "P@ssw0rd", "qwertyuiop",
];

/** Standard wordlist locations, autoloaded when present (largest first). */
const AUTOLOAD_WORDLISTS = [
  "/usr/share/wordlists/rockyou.txt",
  "/opt/seclists/Passwords/Leaked-Databases/rockyou-70.txt",
  "/opt/seclists/Passwords/Leaked-Databases/rockyou-35.txt",
  "/opt/seclists/Passwords/Leaked-Databases/rockyou-40.txt",
  "/opt/seclists/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt",
  "/opt/seclists/Passwords/Common-Credentials/10k-most-common.txt",
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

function hashMatches(type: string, pw: string, hash: string): boolean {
  const target = hash.toLowerCase();
  if (type === "md5") return createHash("md5").update(pw).digest("hex") === target;
  if (type === "sha1") return createHash("sha1").update(pw).digest("hex") === target;
  if (type === "sha256") return createHash("sha256").update(pw).digest("hex") === target;
  if (type === "sha512") return createHash("sha512").update(pw).digest("hex") === target;
  if (type === "ntlm") {
    // NTLM = MD4(UTF-16LE(password)); implemented here so the format cracks offline.
    const md4 = (buf: Buffer): string => {
      // Minimal MD4 implementation (RFC 1320).
      const pad = (s: Buffer): Buffer => {
        const len = s.length;
        const bitLen = len * 8;
        const out = Buffer.concat([s, Buffer.from([0x80])]);
        const mod = out.length % 64;
        const padLen = mod < 56 ? 56 - mod : 120 - mod;
        const padded = Buffer.concat([out, Buffer.alloc(padLen)]);
        const lenBuf = Buffer.alloc(8);
        lenBuf.writeUInt32LE(bitLen >>> 0, 0);
        lenBuf.writeUInt32LE(Math.floor(bitLen / 0x100000000), 4);
        return Buffer.concat([padded, lenBuf]);
      };
      const rotl = (x: number, n: number): number => ((x << n) | (x >>> (32 - n))) >>> 0;
      const F = (x: number, y: number, z: number): number => (x & y) | (~x & z);
      const G = (x: number, y: number, z: number): number => (x & y) | (x & z) | (y & z);
      const H = (x: number, y: number, z: number): number => x ^ y ^ z;
      const msg = pad(buf);
      let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
      for (let i = 0; i < msg.length; i += 64) {
        const X: number[] = [];
        for (let j = 0; j < 16; j++) X[j] = msg.readUInt32LE(i + j * 4);
        let A = a0, B = b0, C = c0, D = d0;
        // Round 1
        for (let r = 0; r < 16; r++) {
          const k = r;
          const s = [3, 7, 11, 19][r % 4];
          const order = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
          A = rotl((A + F(B, C, D) + X[order[k]] + 0) >>> 0, s); [A, B, C, D] = [D, A, B, C];
        }
        // Round 2
        for (let r = 0; r < 16; r++) {
          const order = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
          const s = [3, 5, 9, 13][r % 4];
          A = rotl((A + G(B, C, D) + X[order[r]] + 0x5a827999) >>> 0, s); [A, B, C, D] = [D, A, B, C];
        }
        // Round 3
        for (let r = 0; r < 16; r++) {
          const order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
          const s = [3, 9, 11, 15][r % 4];
          A = rotl((A + H(B, C, D) + X[order[r]] + 0x6ed9eba1) >>> 0, s); [A, B, C, D] = [D, A, B, C];
        }
        a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
      }
      const le = (x: number): Buffer => Buffer.from([x & 0xff, (x >>> 8) & 0xff, (x >>> 16) & 0xff, (x >>> 24) & 0xff]);
      return Buffer.concat([le(a0), le(b0), le(c0), le(d0)]).toString("hex");
    };
    const utf16le = Buffer.from(pw, "utf16le");
    return md4(utf16le) === target;
  }
  return false;
}

/** Stream a set of wordlist files line-by-line, returning the first match. */
async function crackWordlists(hash: string, type: string, paths: string[], maxCandidates: number): Promise<{ password: string | null; checked: number }> {
  let checked = 0;
  for (const p of paths) {
    if (!existsSync(p)) continue;
    const stream = createReadStream(p, { encoding: "utf8" });
    const rl = createInterface({ input: stream, crlfDelay: Infinity });
    let found: string | null = null;
    for await (const line of rl) {
      if (found) break;
      const pw = line.endsWith("\r") ? line.slice(0, -1) : line;
      if (!pw) continue;
      checked += 1;
      if (checked > maxCandidates) break;
      if (hashMatches(type, pw, hash)) found = pw;
    }
    stream.destroy();
    if (found) return { password: found, checked };
    if (checked > maxCandidates) break;
  }
  return { password: null, checked };
}

export interface CrackOptions {
  /** Wordlist file path(s) to try in addition to the autoloaded ones. */
  wordlist?: string | string[];
  /** Upper bound on candidates streamed from wordlists (default 5,000,000). */
  maxCandidates?: number;
}

export async function crackHash(hash: string, extra: string[] = [], opts: CrackOptions = {}): Promise<Record<string, unknown>> {
  const type = identifyHash(hash);
  const maxCandidates = opts.maxCandidates ?? 5_000_000;

  // 1. Fast path: built-in + agent-supplied candidates.
  const fast = [...new Set([...extra, ...COMMON_PASSWORDS])];
  let matched = "";
  for (const pw of fast) {
    if (hashMatches(type, pw, hash)) { matched = pw; break; }
  }
  if (matched) {
    return {
      type, cracked: true, matches: [matched], source: "common",
      recommendation: `CRACKED — authenticate with '${matched}' and continue the chain (login → dashboard → privileged actions).`,
    };
  }

  // 2. Wordlist stream (explicit paths first, then autoload).
  const explicit = opts.wordlist ? (Array.isArray(opts.wordlist) ? opts.wordlist : [opts.wordlist]) : [];
  const paths = [...new Set([...explicit, ...AUTOLOAD_WORDLISTS])];
  const { password, checked } = await crackWordlists(hash, type, paths, maxCandidates);

  if (password) {
    return {
      type, cracked: true, matches: [password], source: "wordlist",
      candidates_checked: checked,
      recommendation: `CRACKED from wordlist — authenticate with '${password}' and continue the chain (login → dashboard → privileged actions).`,
    };
  }

  const mode = HASHCAT_MODE[type];
  return {
    type,
    cracked: false,
    matches: [],
    candidates_checked: checked,
    recommendation: mode
      ? `Not in the built-in common list or ${checked} wordlist candidates. Full crack: hashcat -m ${mode} -a 0 <hashes.txt> <wordlist> (bcrypt cost 12 needs GPU + time). Pass a target-specific wordlist via the wordlist arg (e.g. company names, usernames, pattern guesses). Reuse the credential if it matches another account's hash (password reuse).`
      : "Unknown hash format — save it and identify manually before cracking.",
  };
}
