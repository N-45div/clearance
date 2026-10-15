import { test } from "node:test";
import assert from "node:assert/strict";
import { parseGoMod, stdlibVersion } from "../src/ingest/gomod.ts";
import { ownersFor, parseCodeowners } from "../src/ingest/codeowners.ts";

test("go.mod: requires, indirect, replace and toolchain", () => {
  const mod = parseGoMod(`module github.com/grafana/loki/v3

go 1.24.0

toolchain go1.25.3

require (
	github.com/a/b v1.2.3
	golang.org/x/net v0.38.0 // indirect
	github.com/local/thing v0.0.0
)

require github.com/single/one v0.1.0

replace github.com/a/b => github.com/fork/b v1.2.4
replace github.com/local/thing => ./thing
`);
  assert.equal(mod.module, "github.com/grafana/loki/v3");
  assert.equal(stdlibVersion(mod), "1.25.3");
  assert.deepEqual(mod.requires, [
    { path: "github.com/fork/b", version: "v1.2.4", direct: true },
    { path: "golang.org/x/net", version: "v0.38.0", direct: false },
    { path: "github.com/single/one", version: "v0.1.0", direct: true },
  ]);
  assert.deepEqual(mod.local, ["github.com/local/thing"]);
});

test("go.mod: go line alone gives the stdlib version", () => {
  assert.equal(stdlibVersion(parseGoMod("module x\ngo 1.24\n")), "1.24.0");
  assert.equal(stdlibVersion(parseGoMod("module x\n")), undefined);
});

test("CODEOWNERS: last match wins and people are dropped", () => {
  const rules = parseCodeowners(`# comment
* @grafana/everyone @someone
/pkg/ingester/ @grafana/ingest
docs/ @grafana/docs-squad person@example.com
*.md @grafana/writers
`);
  assert.deepEqual(rules[0]?.teams, ["@grafana/everyone"]);
  assert.equal(ownersFor(rules, "cmd/main.go")?.teams[0], "@grafana/everyone");
  assert.equal(ownersFor(rules, "pkg/ingester/flush.go")?.teams[0], "@grafana/ingest");
  assert.equal(ownersFor(rules, "nested/docs/a.go")?.teams[0], "@grafana/docs-squad");
  assert.equal(ownersFor(rules, "pkg/ingester/README.md")?.teams[0], "@grafana/writers");
});
