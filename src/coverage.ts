/** Coverage matrix (Phase 4).
 *
 * Enumerates, in a machine-readable form, what the framework covers across
 * languages and sink classes — so "coverage" is measured, not claimed.
 */
import { listLanguages } from "./universal-taint.js";
import "./adapters.js";
import { listFrameworks, frameworkProfile } from "./frameworks.js";

const SINK_CLASSES = [
  "sql_execution",
  "code_execution",
  "command_execution",
  "file_operations",
  "file_inclusion",
  "deserialization",
  "http_request",
  "redirect",
  "html_render",
  "xml_processing",
  "archive_extraction",
  "path_traversal",
  "template_injection",
  "xpath_injection",
  "ldap_injection",
];

const PHP_SINKS: Record<string, boolean> = {
  sql_execution: true, code_execution: true, command_execution: true,
  file_operations: true, file_inclusion: true, deserialization: true,
  http_request: true, redirect: true, html_render: true, xml_processing: true,
  archive_extraction: true, path_traversal: true,
  template_injection: true, xpath_injection: true, ldap_injection: true,
};
const JS_SINKS: Record<string, boolean> = {
  sql_execution: true, code_execution: true, command_execution: true,
  file_operations: true, file_inclusion: true, deserialization: false,
  http_request: true, redirect: true, html_render: true, xml_processing: true,
  archive_extraction: true, path_traversal: true,
  template_injection: true, xpath_injection: true, ldap_injection: true,
};
const PY_SINKS: Record<string, boolean> = {
  sql_execution: true, code_execution: true, command_execution: true,
  file_operations: true, file_inclusion: false, deserialization: true,
  http_request: true, redirect: true, html_render: true, xml_processing: true,
  archive_extraction: true, path_traversal: true,
  template_injection: true, xpath_injection: true, ldap_injection: true,
};
const JAVA_SINKS: Record<string, boolean> = {
  sql_execution: true, code_execution: false, command_execution: true,
  file_operations: true, file_inclusion: false, deserialization: true,
  http_request: true, redirect: true, html_render: true, xml_processing: true,
  archive_extraction: true, path_traversal: true,
  template_injection: true, xpath_injection: true, ldap_injection: true,
};
const RUST_SINKS: Record<string, boolean> = {
  sql_execution: true, code_execution: false, command_execution: true,
  file_operations: true, file_inclusion: false, deserialization: true,
  http_request: true, redirect: true, html_render: false, xml_processing: false,
  archive_extraction: false, path_traversal: true,
  template_injection: false, xpath_injection: false, ldap_injection: false,
};

const SINK_BY_LANG: Record<string, Record<string, boolean>> = {
  php: PHP_SINKS,
  javascript: JS_SINKS,
  python: PY_SINKS,
  java: JAVA_SINKS,
  rust: RUST_SINKS,
};

export interface CoverageMatrix {
  languages: Array<{ language: string; extensions: string[] }>;
  sink_coverage: Array<{ sink: string; languages: string[] }>;
  framework_coverage: Array<{ framework: string; language: string; sinks: number; sources: number; sanitizers: number; auth: number; cwe: string[] }>;
  counts: { languages: number; sink_classes: number; covered_pairs: number; total_pairs: number; frameworks: number };
  coverage_ratio: number;
}

export function coverageMatrix(): CoverageMatrix {
  const langs = listLanguages();
  const sinkCoverage: Array<{ sink: string; languages: string[] }> = SINK_CLASSES.map((sink) => {
    const covered = langs
      .map((l) => l.language)
      .filter((lang) => SINK_BY_LANG[lang]?.[sink] === true);
    return { sink, languages: covered };
  });

  // Framework dimension (Phase 5): per-framework knowledge coverage.
  const frameworkCoverage = listFrameworks().map(({ id, language }) => {
    const p = frameworkProfile(id);
    const cwe = p ? [...new Set(p.sinks.map((s) => s.cwe).filter((c): c is string => !!c))].sort() : [];
    return {
      framework: id,
      language,
      sinks: p?.sinks.length ?? 0,
      sources: p?.sources.length ?? 0,
      sanitizers: p?.sanitizers.length ?? 0,
      auth: p?.auth.length ?? 0,
      cwe,
    };
  });

  let coveredPairs = 0;
  for (const lang of langs) {
    for (const sink of SINK_CLASSES) {
      if (SINK_BY_LANG[lang.language]?.[sink]) coveredPairs += 1;
    }
  }
  const totalPairs = langs.length * SINK_CLASSES.length;

  return {
    languages: langs,
    sink_coverage: sinkCoverage,
    framework_coverage: frameworkCoverage,
    counts: {
      languages: langs.length,
      sink_classes: SINK_CLASSES.length,
      covered_pairs: coveredPairs,
      total_pairs: totalPairs,
      frameworks: frameworkCoverage.length,
    },
    coverage_ratio: Number((coveredPairs / totalPairs).toFixed(3)),
  };
}
