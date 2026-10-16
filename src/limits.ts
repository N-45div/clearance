// Caps on the Ask tab, the only part of the app that costs money (a model call). Counters are nodes in
// a small separate graph on the FalkorDB server, so every serverless instance sees the same numbers.
// Visitor IPs are hashed with a salt and their counters expire with the hour; the raw address is never stored.
import { createHash } from "node:crypto";
import { writeLimits } from "./db.ts";

export const PER_IP_PER_HOUR = Number(process.env.ASK_PER_IP_PER_HOUR ?? 20);
export const PER_DAY = Number(process.env.ASK_PER_DAY ?? 300);

export type Verdict = { ok: true } | { ok: false; reason: string; retryAfter: number };

const hash = (ip: string) =>
  createHash("sha256").update(`${process.env.LIMIT_SALT ?? "clearance"}:${ip}`).digest("hex").slice(0, 24);

export function windows(now: Date) {
  const hour = now.toISOString().slice(0, 13);
  const day = now.toISOString().slice(0, 10);
  const nextHour = 3600 - (Math.floor(now.getTime() / 1000) % 3600);
  const nextDay = 86400 - (Math.floor(now.getTime() / 1000) % 86400);
  return { hour, day, nextHour, nextDay };
}

export async function allowAsk(ip: string, now = new Date()): Promise<Verdict> {
  const w = windows(now);
  const secs = Math.floor(now.getTime() / 1000);
  // One query, so both counters move together; MERGE + SET runs atomically on the server.
  const [n] = await writeLimits<{ perIp: number; perDay: number }>(
    `MERGE (a:Counter {key: $ipKey}) ON CREATE SET a.n = 0, a.expires = $ipExpires
     SET a.n = a.n + 1
     MERGE (d:Counter {key: $dayKey}) ON CREATE SET d.n = 0, d.expires = $dayExpires
     SET d.n = d.n + 1
     RETURN a.n AS perIp, d.n AS perDay`,
    {
      ipKey: `ask:ip:${hash(ip)}:${w.hour}`, ipExpires: secs + w.nextHour,
      dayKey: `ask:day:${w.day}`, dayExpires: secs + w.nextDay,
    },
  );
  await writeLimits(`MATCH (c:Counter) WHERE c.expires < $now DELETE c`, { now: secs });
  if ((n?.perDay ?? 0) > PER_DAY) return { ok: false, reason: `the demo's daily limit of ${PER_DAY} questions is used up`, retryAfter: w.nextDay };
  if ((n?.perIp ?? 0) > PER_IP_PER_HOUR) return { ok: false, reason: `the limit of ${PER_IP_PER_HOUR} questions per visitor per hour is reached`, retryAfter: w.nextHour };
  return { ok: true };
}

// MCP tool calls cost no model money, but each one is a query on the free instance: a looser per-visitor cap.
export const MCP_PER_IP_PER_HOUR = Number(process.env.MCP_PER_IP_PER_HOUR ?? 300);

export async function allowMcp(ip: string, now = new Date()): Promise<Verdict> {
  const w = windows(now);
  const secs = Math.floor(now.getTime() / 1000);
  const [n] = await writeLimits<{ perIp: number }>(
    `MERGE (a:Counter {key: $key}) ON CREATE SET a.n = 0, a.expires = $expires
     SET a.n = a.n + 1
     RETURN a.n AS perIp`,
    { key: `mcp:ip:${hash(ip)}:${w.hour}`, expires: secs + w.nextHour },
  );
  if ((n?.perIp ?? 0) > MCP_PER_IP_PER_HOUR) {
    return { ok: false, reason: `the limit of ${MCP_PER_IP_PER_HOUR} MCP requests per visitor per hour is reached`, retryAfter: w.nextHour };
  }
  return { ok: true };
}

export function clientIp(headers: Headers): string {
  return headers.get("x-real-ip") ?? headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "local";
}
