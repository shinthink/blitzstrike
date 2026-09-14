/** `param_surface` — autonomous parameter discovery.
 *
 *  Rather than testing only a hinted parameter, this fetches the target and
 *  extracts EVERY testable parameter: URL query params, HTML form fields,
 *  path-segment identifiers (/users/123, UUIDs), and JS-referenced endpoints —
 *  then (optionally) attaches the per-class discovery + test hints so the agent
 *  knows WHERE to look and WHAT to drive for a given vulnerability class.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { crawlLinks, extractParams } from "./live-recon.js";

const ROOT = join(fileURLToPath(new URL(".", import.meta.url)), "..");

interface SpecialistHint {
  id: string;
  discover: string;
  test: string;
  tools: string[];
}

function loadSpecialists(): SpecialistHint[] {
  try {
    return (JSON.parse(readFileSync(join(ROOT, "intelligence", "specialist-discovery.json"), "utf8")) as { classes: SpecialistHint[] }).classes;
  } catch {
    return [];
  }
}

function formFields(html: string): string[] {
  const out = new Set<string>();
  const re = /<(?:input|select|textarea|button)\b[^>]*\bname\s*=\s*["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) if (m[1] && !/^(csrf|_csrf|token|_token)$/i.test(m[1])) out.add(m[1]);
  return [...out];
}

function pathParams(urls: string[]): Array<{ name: string; sample: string; kind: "id" | "uuid" | "slug" }> {
  const seen = new Set<string>();
  const out: Array<{ name: string; sample: string; kind: "id" | "uuid" | "slug" }> = [];
  const uuidRe = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
  for (const u of urls) {
    let path = "";
    try {
      path = new URL(u).pathname;
    } catch {
      continue;
    }
    const segs = path.split("/").filter(Boolean);
    for (let i = 0; i < segs.length; i++) {
      const s = segs[i];
      const prev = segs[i - 1] ?? "id";
      if (/^\d+$/.test(s)) {
        const name = prev.replace(/[^a-z0-9_]/gi, "").toLowerCase() || "id";
        const key = `${name}:id`;
        if (!seen.has(key)) {
          seen.add(key);
          out.push({ name, sample: s, kind: "id" });
        }
      } else if (uuidRe.test(s)) {
        const name = prev.replace(/[^a-z0-9_]/gi, "").toLowerCase() || "uuid";
        const key = `${name}:uuid`;
        if (!seen.has(key)) {
          seen.add(key);
          out.push({ name, sample: s, kind: "uuid" });
        }
      }
    }
  }
  return out;
}

function jsRefs(html: string): string[] {
  const out = new Set<string>();
  for (const m of html.matchAll(/(?:fetch|axios(?:\.get|\.post)?|XMLHttpRequest\.open)\s*\(\s*["'`]([^"'`]+)["'`]/gi)) {
    const u = m[1];
    if (/^https?:\/\//i.test(u) || u.startsWith("/")) out.add(u);
  }
  return [...out].slice(0, 50);
}

export interface ParamSurfaceResult {
  target: string;
  url: string;
  status_hint?: string;
  query_params: string[];
  form_fields: string[];
  path_params: Array<{ name: string; sample: string; kind: "id" | "uuid" | "slug" }>;
  js_refs: string[];
  total: number;
  specialist_hints?: SpecialistHint[];
}

export async function paramSurface(target: string, class_?: string): Promise<ParamSurfaceResult> {
  const base = target.replace(/\/$/, "");
  let html = "";
  let status = 0;
  try {
    const res = await fetch(target, { redirect: "follow", headers: { "User-Agent": "Mozilla/5.0 (compatible; BlitzStrike/2.4)" } });
    status = res.status;
    html = await res.text();
  } catch {
    /* fetch failed — continue with empty */
  }

  const { links, scripts } = crawlLinks(base, html);
  const allUrls = [target, ...links, ...scripts];
  const query = extractParams(allUrls);
  const fields = formFields(html);
  const paths = pathParams(allUrls);
  const js = jsRefs(html);

  const result: ParamSurfaceResult = {
    target,
    url: base,
    query_params: query,
    form_fields: fields,
    path_params: paths,
    js_refs: js,
    total: query.length + fields.length + paths.length,
  };

  if (class_) {
    const spec = loadSpecialists();
    const c = class_.toLowerCase().trim();
    const matched = spec.filter((s) => s.id === c || s.id.includes(c) || c.includes(s.id));
    result.specialist_hints = matched.length > 0 ? matched : spec.filter((s) => s.id.includes(c.slice(0, 3)));
  } else {
    result.specialist_hints = loadSpecialists();
  }

  return { ...result, url: base, status_hint: status === 0 ? "fetch failed" : `http ${status}` };
}
