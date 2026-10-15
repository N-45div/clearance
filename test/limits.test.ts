import { test } from "node:test";
import assert from "node:assert/strict";
import { clientIp, windows } from "../src/limits.ts";

test("limit windows roll over on the hour and the UTC day", () => {
  const w = windows(new Date("2026-10-16T05:59:30Z"));
  assert.equal(w.hour, "2026-10-16T05");
  assert.equal(w.day, "2026-10-16");
  assert.equal(w.nextHour, 30);
  assert.equal(w.nextDay, 18 * 3600 + 30);
});

test("the client address comes from the proxy headers", () => {
  assert.equal(clientIp(new Headers({ "x-forwarded-for": "203.0.113.7, 10.0.0.1" })), "203.0.113.7");
  assert.equal(clientIp(new Headers({ "x-real-ip": "198.51.100.2", "x-forwarded-for": "203.0.113.7" })), "198.51.100.2");
  assert.equal(clientIp(new Headers()), "local");
});
