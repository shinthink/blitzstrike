/** Verification harness — a self-contained, reproducible TP/FP report.
 *
 *  Every detector is exercised against a POSITIVE fixture (must fire) and a
 *  NEGATIVE fixture (must stay silent). The harness reports, per detector,
 *  whether it was a true positive (TP) + true negative (TN) — or a false
 *  negative (FN) / false positive (FP). This turns "battle-tested" from a claim
 *  into a command anyone can run: `blitzstrike verify`.
 *
 *  The cross-file `priv_esc` detector needs a file tree (not an inline fixture),
 *  so it is covered separately by the verification corpus + the cross-file
 *  regression test.
 */
import { detectComplexBugs } from "./complex-bugs.js";

interface VerifyCase {
  id: string;
  detector: string;
  positive: string;
  negative: string;
  /** Optional file name/extension for manifest-gated detectors (dependency_confusion). */
  file?: string;
}

const PHP = (body: string): string => `<?php\n${body}\n`;

const CASES: VerifyCase[] = [
  {
    id: "deserialization",
    detector: "deserialization",
    positive: PHP(`$o = unserialize($_GET['data']);\nclass A { function __destruct() { system($this->c); } }`),
    negative: PHP(`$o = json_decode($_GET['data'], true);`),
  },
  {
    id: "type-juggling",
    detector: "type_juggling",
    positive: PHP(`$hash = "0e1234567890";\nif ($_GET['pwd'] == $hash) { login(); }`),
    negative: PHP(`if (hash_equals($_GET['pwd'], $hash)) { login(); }`),
  },
  {
    id: "mass-assignment",
    detector: "mass_assignment",
    positive: PHP(`extract($_POST);`),
    negative: PHP(`extract($data, EXTR_SKIP);`),
  },
  {
    id: "prototype-pollution",
    detector: "prototype_pollution",
    positive: PHP(`const merged = deepMerge({}, JSON.parse(req.body));`),
    negative: PHP(`const merged = Object.assign({}, { a: 1 });`),
  },
  {
    id: "crlf-injection",
    detector: "crlf_injection",
    positive: PHP(`header("Location: " . $_GET['url']);`),
    negative: PHP(`header("Location: /fixed");`),
  },
  {
    id: "path-traversal",
    detector: "path_confusion",
    positive: PHP(`include($_GET['page'] . ".php");`),
    negative: PHP(`include('views/' . basename($_GET['page']) . '.php');`),
  },
  {
    id: "ssrf",
    detector: "ssrf",
    positive: PHP(`$r = file_get_contents($_GET['url']);`),
    negative: PHP(`$r = file_get_contents('https://api.fixed.example/x');`),
  },
  {
    id: "xxe",
    detector: "xxe",
    positive: PHP(`$x = simplexml_load_string($_POST['xml']);`),
    negative: PHP(`$x = json_decode($_POST['data']);`),
  },
  {
    id: "ssti",
    detector: "ssti",
    positive: PHP(`return render_template_string($_GET['tpl']);`),
    negative: PHP(`return render_template('fixed.html');`),
  },
  {
    id: "wrong-sanitizer",
    detector: "wrong_sanitizer",
    positive: PHP(`$x = htmlspecialchars($_GET['q']);\n$wpdb->query("SELECT * FROM t WHERE c='" . $x . "'");`),
    negative: PHP(`$x = $wpdb->prepare("SELECT * FROM t WHERE c=%s", $_GET['q']);`),
  },
  {
    id: "missing-authz",
    detector: "missing_authz",
    positive: PHP(`add_action('wp_ajax_nopriv_set_opt', 'h');\nfunction h() { update_option('x', $_POST['x']); }`),
    negative: PHP(`add_action('wp_ajax_set_opt', 'h');\nfunction h() { if (!current_user_can('manage_options')) wp_die(); update_option('x', $_POST['x']); }`),
  },
  {
    id: "missing-nonce",
    detector: "missing_nonce",
    positive: PHP(`add_action('wp_ajax_del', 'h');\nfunction h() { wp_delete_post((int)$_POST['id']); }`),
    negative: PHP(`add_action('wp_ajax_del', 'h');\nfunction h() { check_ajax_referer('n'); wp_delete_post((int)$_POST['id']); }`),
  },
  {
    id: "file-upload",
    detector: "file_upload",
    positive: PHP(`$f = $_FILES['up'];\nmove_uploaded_file($f['tmp_name'], '/uploads/' . $f['name']);`),
    negative: PHP(`$f = $_FILES['up'];\nif (in_array(pathinfo($f['name'], PATHINFO_EXTENSION), ['jpg','png'])) move_uploaded_file($f['tmp_name'], '/uploads/' . $f['name']);`),
  },
  {
    id: "sql-injection",
    detector: "sql_injection",
    positive: PHP(`$wpdb->get_results("SELECT * FROM t WHERE id=" . $id);`),
    negative: PHP(`$wpdb->get_results($wpdb->prepare("SELECT * FROM t WHERE id=%d", $id));`),
  },
  {
    id: "hardcoded-secret",
    detector: "hardcoded_secret",
    positive: PHP(`$api_key = "EXAMPLE_API_KEY_123456789";`),
    negative: PHP(`$api_key = getenv("API_KEY");`),
  },
  {
    id: "llm-injection",
    detector: "llm_injection",
    positive: PHP(`$u = $_POST['msg'];\n$r = openai.chat.completions.create(['messages' => [['role' => 'user', 'content' => $u]]]);`),
    negative: PHP(`$r = openai.chat.completions.create(['messages' => [['role' => 'user', 'content' => 'hello']]]);`),
  },
  {
    id: "graphql-exposure",
    detector: "graphql_exposure",
    positive: PHP(`$srv = new ApolloServer({ introspection: true, playground: true });`),
    negative: PHP(`$srv = new ApolloServer({ introspection: false });`),
  },
  {
    id: "oauth-misconfig",
    detector: "oauth_misconfig",
    positive: PHP(`$redirect_uri = $_GET['redirect_uri'];`),
    negative: PHP(`$redirect_uri = 'https://app.example.com/callback';`),
  },
  {
    id: "grpc-reflection",
    detector: "grpc_reflection",
    positive: PHP(`$server->addService(enable_server_reflection());`),
    negative: PHP(`$server->addService($my_service);`),
  },
  {
    id: "dependency-confusion",
    detector: "dependency_confusion",
    file: "requirements.txt",
    positive: `--extra-index-url https://pypi.org/simple\\nnumpy==1.24.0\\n`,
    negative: `--index-url https://pypi.internal.company.com/simple\\nnumpy==1.24.0\\n`,
  },
  {
    id: "ml-supply-chain",
    detector: "ml_supply_chain",
    file: "train.py",
    positive: `import torch\\nmodel = torch.load(downloaded_model)\\n`,
    negative: `import torch\\nmodel = torch.load("model.pt", weights_only=True)\\n`,
  },
  {
    id: "rust-unsafe",
    detector: "rust_unsafe",
    file: "lib.rs",
    positive: `fn f() { let x: &[u8] = std::mem::transmute(user_data); }\\n`,
    negative: `fn f() { let x: &[u8] = user_data.as_bytes(); }\\n`,
  },
  {
    id: "rust-format-string",
    detector: "rust_format_string",
    file: "main.rs",
    positive: `fn f() { println!(user_input); }\n`,
    negative: `fn f() { println!("{}", user_input); }\n`,
  },
  {
    id: "jwt-alg-confusion",
    detector: "jwt_alg_confusion",
    file: "auth.js",
    positive: `function verify(t){ if(t.alg==='RS256'){ verifier.verify(KEYS.publicKey); } else if(t.alg==='HS256'){ crypto.createHmac('sha256', KEYS.publicKey).update(d).digest(); } }\n`,
    negative: `function verify(t){ if(t.alg==='RS256'){ verifier.verify(KEYS.publicKey); } else { throw new Error('unsupported alg'); } }\n`,
  },
  {
    id: "cache-deception",
    detector: "cache_deception",
    file: "nginx.conf",
    positive: `location ~* \.(css|js|png|jpg|gif|ico|svg)$ { proxy_cache ctf_cache; proxy_cache_valid 200 5m; }\nproxy_cache_key "$scheme$request_method$request_uri";\n`,
    negative: `location / { proxy_pass http://backend; }\n`,
  },
  {
    id: "cors-misconfig",
    detector: "cors_misconfiguration",
    file: "server.js",
    positive: `res.setHeader('Access-Control-Allow-Origin', req.headers.origin);\nres.setHeader('Access-Control-Allow-Credentials', 'true');\n`,
    negative: `res.setHeader('Access-Control-Allow-Origin', 'https://app.example.com');\n`,
  },
  {
    id: "xss-dom-sink",
    detector: "xss",
    file: "page.js",
    positive: `const u = new URLSearchParams(location.search).get('name');\ndocument.getElementById('out').innerHTML = u;\n`,
    negative: `document.getElementById('out').innerHTML = '<b>static</b>';\n`,
  },
  {
    id: "subdomain-takeover",
    detector: "subdomain_takeover",
    file: "dns.tf",
    positive: `resource "aws_route53_record" "blog" { name = "blog.example.com" type = "CNAME" records = ["oldblog.github.io"] }\n`,
    negative: `resource "aws_route53_record" "www" { name = "www.example.com" type = "A" records = ["1.2.3.4"] }\n`,
  },
];

export interface VerifyCaseResult {
  id: string;
  detector: string;
  positive_fired: boolean;
  negative_fired: boolean;
  tp: boolean;
  tn: boolean;
  status: "pass" | "fn" | "fp";
}

export interface VerificationReport {
  total: number;
  passed: number;
  failed: number;
  tp_count: number;
  fp_count: number;
  fn_count: number;
  cases: VerifyCaseResult[];
}

/** Run every detector against its positive + negative fixture and report TP/FP. */
export function runVerificationHarness(): VerificationReport {
  const cases: VerifyCaseResult[] = CASES.map((c) => {
    const pos = detectComplexBugs(c.positive, c.file ?? "positive.php").filter((f) => f.type === c.detector);
    const neg = detectComplexBugs(c.negative, c.file ?? "negative.php").filter((f) => f.type === c.detector);
    const positive_fired = pos.length > 0;
    const negative_fired = neg.length > 0;
    const tp = positive_fired;
    const tn = !negative_fired;
    const status: VerifyCaseResult["status"] = tp && tn ? "pass" : !tp ? "fn" : "fp";
    return { id: c.id, detector: c.detector, positive_fired, negative_fired, tp, tn, status };
  });

  const passed = cases.filter((c) => c.status === "pass").length;
  return {
    total: cases.length,
    passed,
    failed: cases.length - passed,
    tp_count: cases.filter((c) => c.tp).length,
    fp_count: cases.filter((c) => c.status === "fp").length,
    fn_count: cases.filter((c) => c.status === "fn").length,
    cases,
  };
}

/** A compact, terminal-friendly text report. */
export function verificationReportText(): string {
  const r = runVerificationHarness();
  const lines: string[] = [];
  lines.push(`Blitz Strike verification harness`);
  lines.push(`  ${r.passed}/${r.total} detectors pass (TP + TN) · TP ${r.tp_count} · FP ${r.fp_count} · FN ${r.fn_count}`);
  lines.push(``);
  for (const c of r.cases) {
    const mark = c.status === "pass" ? "OK " : c.status === "fn" ? "FN " : "FP ";
    lines.push(`  [${mark}] ${c.id.padEnd(20)} pos=${c.positive_fired ? "hit" : "miss"} neg=${c.negative_fired ? "HIT" : "clean"}`);
  }
  if (r.failed > 0) {
    lines.push(``);
    lines.push(`  ${r.failed} detector(s) failed — see the cases above (FN = missed a positive, FP = fired on clean code).`);
  }
  return lines.join("\n");
}
