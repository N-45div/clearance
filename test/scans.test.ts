import { test } from "node:test";
import assert from "node:assert/strict";
import { callFacts, funcKey, levelOf, parseScan, repoPath, type Finding, type Scan } from "../src/ingest/scans.ts";

const MOD = "go.k6.io/k6/v2";

// Shapes copied from govulncheck v1.9.0 output for grafana/k6.
const moduleOnly: Finding = { osv: "GO-2026-5932", trace: [{ module: "golang.org/x/crypto", version: "v0.58.0" }] };
const imported: Finding = {
  osv: "GO-2026-0001",
  trace: [{ module: "golang.org/x/net", version: "v0.40.0", package: "golang.org/x/net/html" }],
};
const called: Finding = {
  osv: "GO-2026-0002",
  trace: [
    { module: "github.com/gorilla/websocket", version: "v1.5.3", package: "github.com/gorilla/websocket", function: "DialContext", receiver: "*Dialer", position: { filename: "client.go", line: 302 } },
    { module: MOD, package: `${MOD}/internal/browser/common`, function: "NewConnection", position: { filename: "internal/browser/common/connection.go", line: 165 } },
    { module: MOD, package: `${MOD}/cmd`, function: "main", position: { filename: "cmd/main.go", line: 9 } },
  ],
};
// govulncheck also reports the weaker levels for a called vulnerability.
const calledModuleLevel: Finding = { osv: "GO-2026-0002", trace: [{ module: "github.com/gorilla/websocket", version: "v1.5.3" }] };

test("levelOf reads how deep a finding reaches", () => {
  assert.equal(levelOf(moduleOnly), "module");
  assert.equal(levelOf(imported), "package");
  assert.equal(levelOf(called), "symbol");
});

test("funcKey matches the Go vulndb symbol naming", () => {
  assert.equal(funcKey(called.trace[0]!), "github.com/gorilla/websocket.Dialer.DialContext");
  assert.equal(funcKey(called.trace[2]!), `${MOD}/cmd.main`);
});

test("callFacts keeps the strongest level and the call chain toward the vulnerable function", () => {
  const scan: Scan = { config: undefined, findings: [calledModuleLevel, moduleOnly, imported, called] };
  const facts = callFacts(scan);
  assert.equal(facts.levels.get("GO-2026-0002"), "symbol");
  assert.equal(facts.levels.get("GO-2026-5932"), "module");
  assert.equal(facts.levels.get("GO-2026-0001"), "package");
  assert.deepEqual([...facts.imports].sort(), ["github.com/gorilla/websocket", "golang.org/x/net/html"]);
  assert.deepEqual([...facts.calls.keys()], [
    `${MOD}/internal/browser/common.NewConnection>github.com/gorilla/websocket.Dialer.DialContext`,
    `${MOD}/cmd.main>${MOD}/internal/browser/common.NewConnection`,
  ]);
  assert.deepEqual([...facts.entries.keys()], [`${MOD}/cmd.main`]);
  // Only the reported vulnerable call is a target; frames in between are just hops.
  assert.deepEqual([...facts.vulnerable], ["github.com/gorilla/websocket.Dialer.DialContext"]);
});

test("repoPath only maps frames in the repo's own module", () => {
  assert.equal(repoPath(called.trace[1]!, MOD), "internal/browser/common/connection.go");
  assert.equal(repoPath(called.trace[0]!, MOD), undefined);
});

test("parseScan reads govulncheck's indented JSON stream and the one-object-per-line form alike", () => {
  const messages = [
    { config: { scanner_version: "v1.9.0", go_version: "go1.26.3", db_last_modified: "2026-10-08T22:31:09Z", scan_level: "symbol" } },
    { progress: { message: "Scanning your code {and} \"quoted\" text" } },
    { finding: { osv: "GO-2026-6609", trace: [{ module: "stdlib", package: "net/http", function: "ServeHTTP", receiver: "fileHandler" }] } },
  ];
  const indented = messages.map((m) => JSON.stringify(m, null, 2)).join("\n");
  const compact = messages.map((m) => JSON.stringify(m)).join("\n");
  for (const text of [indented, compact]) {
    const scan = parseScan(text);
    assert.equal(scan.config?.scanner_version, "v1.9.0");
    assert.equal(scan.findings.length, 1);
    assert.equal(scan.findings[0]?.osv, "GO-2026-6609");
  }
  assert.throws(() => parseScan(indented.slice(0, -3)), /truncated/);
});
