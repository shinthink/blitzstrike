/** HTTP-level asset fingerprinting — the signals a live target exposes that
 *  source-code detection cannot see. Shodan-style asset fingerprint:
 *  a favicon's MurmurHash3 (MMH3) is a stable product/tech identity — the SAME
 *  favicon hash means the SAME product even across unrelated hosts, so it is the
 *  single strongest pivoting signal for fingerprinting + dedup of web assets.
 */

import { sha256 } from "./evidence.js";

/** MurmurHash3 (x86 32-bit), seed 0 — the exact variant Shodan uses for
 *  `http.favicon.hash` (and the value returned by the python `mmh3` package).
 *  Returns the SIGNED 32-bit result (e.g. -1492936408), matching Shodan's API. */
export function mmh3(data: Uint8Array, seed = 0): number {
  const c1 = 0xcc9e2d51;
  const c2 = 0x1b873593;
  let h1 = seed | 0;
  const len = data.length;
  const nblocks = len >> 2;

  for (let i = 0; i < nblocks; i++) {
    const o = i << 2;
    let k1 = (data[o] | (data[o + 1] << 8) | (data[o + 2] << 16) | (data[o + 3] << 24)) | 0;
    k1 = Math.imul(k1, c1) | 0;
    k1 = (k1 << 15) | (k1 >>> 17);
    k1 = Math.imul(k1, c2) | 0;
    h1 ^= k1;
    h1 = (h1 << 13) | (h1 >>> 19);
    h1 = (Math.imul(h1, 5) + 0xe6546b64) | 0;
  }

  let k1 = 0;
  const tail = nblocks << 2;
  switch (len & 3) {
    case 3:
      k1 ^= data[tail + 2] << 16;
    // fallthrough
    case 2:
      k1 ^= data[tail + 1] << 8;
    // fallthrough
    case 1:
      k1 ^= data[tail];
      k1 = Math.imul(k1, c1) | 0;
      k1 = (k1 << 15) | (k1 >>> 17);
      k1 = Math.imul(k1, c2) | 0;
      h1 ^= k1;
  }

  h1 ^= len;
  h1 ^= h1 >>> 16;
  h1 = Math.imul(h1, 0x85ebca6b) | 0;
  h1 ^= h1 >>> 13;
  h1 = Math.imul(h1, 0xc2b2ae35) | 0;
  h1 ^= h1 >>> 16;
  return h1 | 0;
}

/** Favicon hash (Shodan `http.favicon.hash`) — MMH3 of the raw favicon bytes. */
export function faviconHash(bytes: Uint8Array): number {
  return mmh3(bytes, 0);
}

/** The full asset-fingerprint bundle: every signal a live HTTP asset exposes,
 *  matching the Shodan asset model. Pass the raw favicon bytes and
 *  the response body, and it returns the fingerprint fields for dedup + tech
 *  pivoting. `favicon_mmh3` is the Shodan-compatible signed int; `favicon_mmh3_b64`
 *  is the base64 of the raw 32-bit result (the `mmh3:` form fingerprint DBs use). */
export interface AssetFingerprint {
  favicon_mmh3: number | null;
  favicon_mmh3_b64: string | null;
  body_sha256: string;
}

export function fingerprintBundle(faviconBytes: Uint8Array | null, body: string): AssetFingerprint {
  let favicon_mmh3: number | null = null;
  let favicon_mmh3_b64: string | null = null;
  if (faviconBytes && faviconBytes.length > 0) {
    favicon_mmh3 = faviconHash(faviconBytes);
    const buf = new ArrayBuffer(4);
    const dv = new DataView(buf);
    dv.setInt32(0, favicon_mmh3, false);
    favicon_mmh3_b64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
  }
  return { favicon_mmh3, favicon_mmh3_b64, body_sha256: sha256(body) };
}

/** Decode a base64/hex favicon payload into bytes (for the tool boundary, which
 *  passes raw favicon bytes as text). Returns null on invalid input. */
export function decodeFavicon(data: string, encoding: "base64" | "hex" = "base64"): Uint8Array | null {
  try {
    if (encoding === "hex") {
      const s = data.replace(/[^0-9a-fA-F]/g, "");
      if (s.length % 2 !== 0 || s.length === 0) return null;
      const out = new Uint8Array(s.length / 2);
      for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
      return out;
    }
    const bin = atob(data);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}
