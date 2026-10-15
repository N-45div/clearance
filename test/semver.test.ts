import { test } from "node:test";
import assert from "node:assert/strict";
import { compare, fixedAfter } from "../src/ingest/semver.ts";

test("compare orders Go versions, pre-releases first", () => {
  assert.equal(compare("v0.60.0", "v0.59.9"), 1);
  assert.equal(compare("1.26.9", "1.26.10"), -1);
  assert.equal(compare("1.27.0-0", "1.27.0"), -1);
  assert.equal(compare("v1.2.3", "1.2.3"), 0);
  assert.equal(compare("v0.0.0-20240101000000-abcdef", "v0.0.1"), -1);
});

test("fixedAfter picks the lowest fix above the version in use", () => {
  const events = [{ introduced: "0" }, { fixed: "1.26.9" }, { introduced: "1.27.0-0" }, { fixed: "1.27.2" }];
  assert.equal(fixedAfter("1.25.3", events), "1.26.9");
  assert.equal(fixedAfter("1.27.1", events), "1.27.2");
  assert.equal(fixedAfter("1.27.2", events), undefined);
});
