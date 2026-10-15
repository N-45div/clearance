import { test } from "node:test";
import assert from "node:assert/strict";
import { isShipping } from "../src/graph/verdicts.ts";

test("entry points under examples, tests and tooling do not ship", () => {
  assert.equal(isShipping("examples/secrets/mock_server.go"), false);
  assert.equal(isShipping("integration/mock-service/main.go"), false);
  assert.equal(isShipping("pkg/e2e/run.go"), false);
  assert.equal(isShipping("tools/doc-generator/main.go"), false);
  assert.equal(isShipping("cmd/k6/main.go"), true);
  assert.equal(isShipping("pkg/api/activity_tracking.go"), true);
  assert.equal(isShipping("internal/testingstuff.go"), true);
  // Unknown entry file: never downgrade on a guess.
  assert.equal(isShipping(null), true);
});
