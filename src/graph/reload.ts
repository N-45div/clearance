// A free FalkorDB Cloud instance keeps nothing across a restart. When the fleet graph is gone, rebuild
// it from the same public sources and the committed scans, and decide the verdicts again. Only one
// rebuild runs at a time: a lock node in the limits graph, taken atomically, expires after 10 minutes.
import { read, writeLimits } from "../db.ts";
import { ingest } from "../ingest/run.ts";
import { decideAll, record } from "./verdicts.ts";

export const isMissingGraph = (e: unknown) => /empty key/i.test(String((e as Error)?.message ?? e));

export async function graphIsEmpty(): Promise<boolean> {
  try {
    const [r] = await read<{ n: number }>(`MATCH (r:Repo) RETURN count(r) AS n`);
    return !r?.n;
  } catch (e) {
    if (isMissingGraph(e)) return true;
    throw e;
  }
}

async function takeLock(seconds: number): Promise<boolean> {
  const now = Math.floor(Date.now() / 1000);
  const [r] = await writeLimits<{ free: boolean }>(
    `MERGE (l:Lock {key: 'reload'}) ON CREATE SET l.until = 0
     WITH l, l.until < $now AS free
     SET l.until = CASE WHEN free THEN $until ELSE l.until END
     RETURN free`,
    { now, until: now + seconds },
  );
  return !!r?.free;
}

async function releaseLock() {
  await writeLimits(`MATCH (l:Lock {key: 'reload'}) SET l.until = 0`);
}

export type ReloadResult = { reloaded: boolean; reason: string; verdicts?: number; ms?: number };

export async function reloadIfEmpty(log: (line: string) => void = console.log): Promise<ReloadResult> {
  if (!(await graphIsEmpty())) return { reloaded: false, reason: "graph present" };
  if (!(await takeLock(600))) return { reloaded: false, reason: "a reload is already running" };
  const started = Date.now();
  try {
    await ingest(log);
    const verdicts = await record(await decideAll());
    return { reloaded: true, reason: "graph was empty", verdicts, ms: Date.now() - started };
  } finally {
    await releaseLock();
  }
}
