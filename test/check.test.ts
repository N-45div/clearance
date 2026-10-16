import { test } from "node:test";
import assert from "node:assert/strict";
import { exitCode, repoName, report, type CheckResult } from "../src/check.ts";
import type { Decision } from "../src/graph/verdicts.ts";

const decision = (over: Partial<Decision>): Decision => ({
  repo: "svc", advisory: "GO-2026-0001", status: "not_affected", justification: "vulnerable_code_not_present",
  bumps: ["stdlib@1.26.0=>1.26.9"], path: [], callSite: null, file: null, owners: [], reach: null, entryFile: null,
  repoSha: "abc", advisoryModified: "2026-10-01T00:00:00Z", reason: "stdlib@1.26.0 required, but no vulnerable package from it is imported",
  ...over,
});

const result = (decisions: Decision[], over: Partial<CheckResult> = {}): CheckResult => ({
  repo: "svc", module: "github.com/acme/svc", sha: "0123456789abcdef", scanOk: true, decisions,
  lines: new Map(), advisories: new Map(), unjudged: [], ...over,
});

const shipped = decision({
  advisory: "GO-2026-0002", status: "affected", justification: null, reach: "shipped",
  path: ["github.com/acme/svc/api.Handler.ServeHTTP", "net/http.fileHandler.ServeHTTP"],
  callSite: "github.com/acme/svc/api.Handler.ServeHTTP", file: "api/handler.go", owners: ["@acme/api"],
});
const examplesOnly = decision({
  advisory: "GO-2026-0003", status: "affected", justification: null, reach: "examples_tests_only",
  path: ["main.main", "net/http.ListenAndServe"], entryFile: "examples/server/main.go",
});

test("exit 1 only when shipped code reaches a vulnerable function (default --fail-on shipped)", () => {
  assert.equal(exitCode(result([decision({})]), "shipped"), 0);
  assert.equal(exitCode(result([examplesOnly]), "shipped"), 0);
  assert.equal(exitCode(result([examplesOnly, shipped]), "shipped"), 1);
});

test("--fail-on any also fails on example-only paths; --fail-on never only reports", () => {
  assert.equal(exitCode(result([examplesOnly]), "any"), 1);
  assert.equal(exitCode(result([shipped]), "never"), 0);
});

test("an unusable scan exits 2 whatever --fail-on says, so CI never reads it as clean", () => {
  const ui = decision({ status: "under_investigation", justification: null, reason: "the reachability scan of this commit failed" });
  for (const f of ["shipped", "any", "never"] as const) assert.equal(exitCode(result([ui], { scanOk: false }), f), 2);
});

test("report: file:line, owner and fix for affected; examples apart; no-vulndb ids named", () => {
  const text = report(
    result([shipped, examplesOnly, decision({})], {
      lines: new Map([["svc|github.com/acme/svc/api.Handler.ServeHTTP", 42]]),
      unjudged: ["GHSA-xxxx-yyyy-zzzz"],
    }),
  );
  assert.match(text, /AFFECTED, reachable from shipped code: 1\n {2}GO-2026-0002 /);
  assert.match(text, /at api\/handler\.go:42 {2}owned by @acme\/api {2}fix: stdlib@1\.26\.0 -> 1\.26\.9/);
  assert.match(text, /affected, only from examples, tests or tooling: 1\n {2}GO-2026-0003 /);
  assert.match(text, /not affected \(proof: no call path\): 1/);
  assert.match(text, /no Go vulndb record, so no function data to judge: GHSA-xxxx-yyyy-zzzz/);
});

test("repo name skips a Go major-version suffix", () => {
  assert.equal(repoName("github.com/grafana/smtprelay/v2"), "smtprelay");
  assert.equal(repoName("go.k6.io/k6/v2"), "k6");
  assert.equal(repoName("github.com/grafana/mimir"), "mimir");
  assert.equal(repoName("example"), "example");
});

test("report: an unusable scan says nothing is proven safe", () => {
  const text = report(result([], { scanOk: false }));
  assert.match(text, /scan is unusable, so every verdict is under investigation and none is "not affected"/);
});
