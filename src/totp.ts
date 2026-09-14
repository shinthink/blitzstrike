/** TOTP / HOTP — deterministic RFC 6238 / RFC 4226 one-time-password generation.
 *
 *  Lets the agent drive 2FA/TOTP-protected logins during authenticated scanning:
 *  generate the current TOTP token from a base32 secret (or a raw ASCII key),
 *  so the agent can fill the 2FA field itself instead of stalling on a prompt.
 */
import { createHmac } from "node:crypto";

function base32Decode(secret: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = secret.toUpperCase().replace(/=+$/g, "").replace(/[\s-]/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function keyFromSecret(secret: string): Buffer {
  const trimmed = secret.trim();
  // Standard TOTP secrets are base32; a raw ASCII key contains non-base32 chars.
  return /^[A-Za-z2-7]+=?$/.test(trimmed) ? base32Decode(trimmed) : Buffer.from(trimmed, "utf8");
}

function hotp(secret: string, counter: number, digits: number, algo: string): string {
  const key = keyFromSecret(secret);
  const buf = Buffer.alloc(8);
  let c = Math.max(0, Math.floor(counter));
  for (let i = 7; i >= 0; i--) {
    buf[i] = c & 0xff;
    c = Math.floor(c / 256);
  }
  const mac = createHmac(algo, key).update(buf).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[offset] & 0x7f) << 24) | ((mac[offset + 1] & 0xff) << 16) | ((mac[offset + 2] & 0xff) << 8) | (mac[offset + 3] & 0xff);
  return String(bin % 10 ** digits).padStart(digits, "0");
}

export interface TotpResult {
  token: string;
  expires_in: number;
  algorithm: string;
  digits: number;
  period: number;
  secret_format: "base32" | "raw";
}

export function totp(secret: string, opts?: { digits?: number; period?: number; algo?: string }): TotpResult {
  const digits = opts?.digits ?? 6;
  const period = opts?.period ?? 30;
  const algo = opts?.algo ?? "sha1";
  const now = Math.floor(Date.now() / 1000);
  const counter = Math.floor(now / period);
  const token = hotp(secret, counter, digits, algo);
  return {
    token,
    expires_in: period - (now % period),
    algorithm: algo,
    digits,
    period,
    secret_format: /^[A-Za-z2-7]+=?$/.test(secret.trim()) ? "base32" : "raw",
  };
}

export function hotpToken(secret: string, counter: number, opts?: { digits?: number; algo?: string }): string {
  return hotp(secret, counter, opts?.digits ?? 6, opts?.algo ?? "sha1");
}
