import { test } from "node:test";
import assert from "node:assert/strict";
import { issueDraft, vexDocument } from "../src/report.ts";

const ref = { org: "grafana", repo: "k6", sha: "3afb7be136269c18cface16e2751b9fddd42b90a" };

test("OpenVEX: one statement per verdict, with the fields the status needs", () => {
  const doc = vexDocument(
    ref,
    [
      { advisory: "GO-2026-6609", aliases: ["CVE-2026-1"], status: "not_affected", justification: "vulnerable_code_not_in_execute_path", reason: "net/http is imported, but nothing reaches it", bumps: ["stdlib@1.26.0=>1.26.9"] },
      { advisory: "GO-2026-6603", status: "affected", justification: null, reason: "3 calls reach net/http.Server.Serve", bumps: ["stdlib@1.26.0=>1.26.9"] },
      { advisory: "GO-2022-0635", status: "under_investigation", justification: null, reason: "scan failed", bumps: [] },
    ],
    "2026-10-15T00:00:00Z",
    "test",
  );
  assert.equal(doc["@context"], "https://openvex.dev/ns/v0.2.0");
  assert.match(doc["@id"], /^urn:clearance:vex:[0-9a-f]{32}$/);
  const [na, aff, ui] = doc.statements;
  assert.deepEqual(na?.products, [{ "@id": `pkg:github/grafana/k6@${ref.sha}` }]);
  assert.deepEqual(na?.vulnerability, { name: "GO-2026-6609", aliases: ["CVE-2026-1"] });
  assert.equal(na?.justification, "vulnerable_code_not_in_execute_path");
  assert.match(String(aff?.action_statement), /bump stdlib from 1.26.0 to 1.26.9/);
  assert.equal(aff?.justification, undefined);
  assert.equal(ui?.status_notes, "scan failed");
});

test("OpenVEX: with the Go module known, each statement also names it with the vulnerable versions as subcomponents", () => {
  const doc = vexDocument(
    { ...ref, module: "go.k6.io/k6/v2" },
    [
      { advisory: "GO-2026-6609", aliases: ["CVE-2026-1"], status: "not_affected", justification: "vulnerable_code_not_in_execute_path", reason: "nothing reaches it", bumps: ["stdlib@1.26.0=>1.26.9", "golang.org/x/net@v0.40.0=>v0.41.0"] },
      { advisory: "GO-2022-0635", status: "under_investigation", justification: null, reason: "scan failed", bumps: [] },
    ],
    "2026-10-15T00:00:00Z",
    "test",
  );
  const [na, ui] = doc.statements;
  // Trivy names stdlib "pkg:golang/stdlib@v1.26.0" and keeps the module's own "v" prefix.
  assert.deepEqual(na?.products, [
    { "@id": `pkg:github/grafana/k6@${ref.sha}` },
    { "@id": "pkg:golang/go.k6.io/k6/v2", subcomponents: [{ "@id": "pkg:golang/stdlib@v1.26.0" }, { "@id": "pkg:golang/golang.org/x/net@v0.40.0" }] },
  ]);
  // No version to name: only the pinned-commit product, never a bare module that would match every version.
  assert.deepEqual(ui?.products, [{ "@id": `pkg:github/grafana/k6@${ref.sha}` }]);
});

test("issue draft names the call site, its owner and the fix", () => {
  const { title, body } = issueDraft({
    ref,
    advisory: { id: "GO-2026-6603", summary: "HTTP/2 server memory exhaustion", url: "https://pkg.go.dev/vuln/GO-2026-6603" },
    bumps: ["stdlib@1.26.0=>1.26.9"],
    frames: [
      { name: "Client.NewRequest", package: "go.k6.io/k6/v2/cloudapi", module: "go.k6.io/k6/v2", file: "cloudapi/client.go", line: 82, owners: ["@grafana/k6-core"] },
      { name: "NewRequest", package: "net/http", module: "stdlib", file: null, line: null, owners: [] },
    ],
    owners: ["@grafana/k6-core"],
    decidedAt: "2026-10-15T00:00:00Z",
    scanner: "govulncheck v1.9.0",
  });
  assert.equal(title, "GO-2026-6603: HTTP/2 server memory exhaustion (reached from Client.NewRequest)");
  assert.match(body, /blob\/3afb7be136269c18cface16e2751b9fddd42b90a\/cloudapi\/client.go#L82/);
  assert.match(body, /owned by @grafana\/k6-core/);
  assert.match(body, /bump stdlib from 1.26.0 to 1.26.9/);
  assert.doesNotMatch(body, /\n\n\n/);
});
