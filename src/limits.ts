// Caps on the Ask tab, the only part of the app that costs money (a model call). Counters live in
// the FalkorDB server's Redis keyspace so every serverless instance sees the same numbers. Visitor IPs
// are hashed and expire with their window; the raw address is never stored.
import { createHash } from "node:crypto";
import { redis } from "./db.ts";

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
  const r = await redis();
  const w = windows(now);
  const ipKey = `clearance:ask:ip:${hash(ip)}:${w.hour}`;
  const dayKey = `clearance:ask:day:${w.day}`;
  const [perIp, perDay] = await Promise.all([r.incr(ipKey), r.incr(dayKey)]);
  if (perIp === 1) await r.expire(ipKey, w.nextHour + 60);
  if (perDay === 1) await r.expire(dayKey, w.nextDay + 60);
  if (perDay > PER_DAY) return { ok: false, reason: `the demo's daily limit of ${PER_DAY} questions is used up`, retryAfter: w.nextDay };
  if (perIp > PER_IP_PER_HOUR) return { ok: false, reason: `you have asked ${PER_IP_PER_HOUR} questions this hour`, retryAfter: w.nextHour };
  return { ok: true };
}

export function clientIp(headers: Headers): string {
  return headers.get("x-real-ip") ?? headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "local";
}
