# Verification: SQL injection (cross-file raw concatenation)

- **Detector:** `sql_injection` → `detectSqlInjection`
- **Target:** an e-commerce plugin (PHP), report segmenter class
- **Ground truth:** CVE-2024-31002 — `$wpdb->get_results("SELECT ... $segmenting_groupby ...")`
  builds a query by raw string concatenation (not prepared).
- **Result:** TP — the sink at the report segmenter is surfaced (plus same-shape
  siblings in the segmenter classes).

## Evidence

The sink line concatenates a variable into the query string with no `->prepare()`.

## Notes

- This detector targets the CROSS-FILE case: the taint engine already covers same-file
  source→sink, so here the concatenated variable has no visible source in scope — a
  lead to trace back to the request source.
