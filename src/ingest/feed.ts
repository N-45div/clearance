// Keeps the graph current: finds Go advisories that are not in the graph yet, keeps the ones that touch
// a module the fleet builds with, and loads them with their version-level blast radius. The scans
// predate them, so their verdicts read "under investigation, needs a rescan" until the repos are rescanned.
import { read, write } from "../db.ts";
import { loadAdvisories, loadMatches } from "../graph/load.ts";
import { decideAll, record } from "../graph/verdicts.ts";
import { goAdvisory, queryBatch, type GoAdvisory, type Pair } from "./osv.ts";

type IndexEntry = { id: string; modified: string; aliases?: string[] };

export async function vulndbIndex(): Promise<IndexEntry[]> {
  const res = await fetch("https://vuln.go.dev/index/vulns.json", { signal: AbortSignal.timeout(30_000) });
  if (!res.ok) throw new Error(`vuln.go.dev index: HTTP ${res.status}`);
  return (await res.json()) as IndexEntry[];
}

export type FeedResult = { checked: number; unseen: number; loaded: string[]; matches: number; verdictsWritten: number };

// `since` defaults to the oldest vulndb snapshot among the scans; an earlier date replays a past week.
export async function checkFeed(maxNew = 40, sinceOverride?: string): Promise<FeedResult> {
  const known = new Set((await read<{ id: string }>(`MATCH (a:Advisory) RETURN a.id AS id`)).map((x) => x.id));
  const [scan] = await read<{ db: string | null }>(`MATCH (r:Repo) WHERE r.scanDb IS NOT NULL RETURN min(r.scanDb) AS db`);
  const since = Date.parse(sinceOverride ?? scan?.db ?? "1970-01-01");
  const index = await vulndbIndex();
  // Only advisories changed after the scans' snapshot can be new to the fleet; the rest were already matched.
  const unseen = index.filter((e) => !known.has(e.id) && Date.parse(e.modified) > since).slice(0, maxNew);

  const versions = await read<{ path: string; version: string }>(
    `MATCH (v:ModuleVersion)<-[:REQUIRES|BUILT_WITH]-(:Repo) RETURN DISTINCT v.path AS path, v.version AS version`,
  );
  const fleetModules = new Set(versions.map((v) => v.path));
  const relevant = new Map<string, GoAdvisory>();
  for (const e of unseen) {
    const adv = await goAdvisory(e.id);
    if (adv.affected.some((a) => fleetModules.has(a.module))) relevant.set(adv.id, adv);
  }
  if (!relevant.size) return { checked: index.length, unseen: unseen.length, loaded: [], matches: 0, verdictsWritten: 0 };

  // Ask OSV only about the fleet's versions of the modules these advisories name.
  const modules = new Set([...relevant.values()].flatMap((a) => a.affected.map((x) => x.module)));
  const pairs: Pair[] = versions.filter((v) => modules.has(v.path));
  const hits = await queryBatch(pairs);
  for (const [k, ids] of hits) hits.set(k, ids.filter((id) => relevant.has(id)));

  await loadAdvisories([...relevant.values()]);
  // The scans never saw these, whatever their publish date says.
  await write(`MATCH (a:Advisory) WHERE a.id IN $ids SET a.addedAfterScan = true`, { ids: [...relevant.keys()] });
  const matches = await loadMatches(hits, relevant, [...relevant.keys()]);
  const verdictsWritten = await record(await decideAll());
  return { checked: index.length, unseen: unseen.length, loaded: [...relevant.keys()], matches, verdictsWritten };
}

if (import.meta.main) {
  const { closeGraph } = await import("../db.ts");
  const i = process.argv.indexOf("--since");
  console.log(await checkFeed(40, i > 0 ? process.argv[i + 1] : undefined));
  await closeGraph();
}
