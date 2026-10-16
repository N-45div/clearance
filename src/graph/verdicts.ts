// Decides every (repo, advisory) verdict from the graph alone, then stores it as a Verdict node.
// A verdict is never edited: when the facts change, a new one SUPERSEDES the old, so the history of
// what was decided, when, and on which commit stays queryable.
import { closeGraph, read, write } from "../db.ts";

export type Status = "affected" | "not_affected" | "under_investigation" | "fixed";
export type Justification = "vulnerable_code_not_present" | "vulnerable_code_not_in_execute_path";

export type Decision = {
  repo: string;
  advisory: string;
  status: Status;
  justification: Justification | null;
  // "module@version=>fix version" for every module version that puts the repo in range
  bumps: string[];
  path: string[]; // func keys from the repo's entry point to the vulnerable function
  callSite: string | null; // the repo's own function closest to the vulnerable code
  file: string | null;
  owners: string[];
  // For affected verdicts: is any path from code that ships, or only from examples, tests and tooling?
  reach: "shipped" | "examples_tests_only" | null;
  entryFile: string | null;
  repoSha: string;
  advisoryModified: string;
  reason: string;
};

// Entry points under these directories are not part of what a repo ships.
export const NON_SHIPPING =
  /(^|\/)(examples?|integration|e2e|tests?|testdata|testing|testutil|hack|tools|scripts|mocks?|benchmarks?|docs?)\//i;

// No file (an entry in a dependency, or unknown) counts as shipped, so a verdict is never downgraded on a guess.
export const isShipping = (file: string | null | undefined) => !file || !NON_SHIPPING.test(file);

// True when the advisory appeared after the vulndb snapshot the repo's scan used.
export const scanPredates = (scanDb: string | null, published: string) =>
  !!scanDb && Date.parse(published) > Date.parse(scanDb);

type Candidate = {
  repo: string; sha: string; scanOk: boolean | null; scanExit: number | null; scanNote: string | null; repoModule: string;
  scanDb: string | null; advisory: string; published: string; modified: string; addedAfterScan: boolean | null;
  bumps: string[];
};

// Every pair a version-only scanner would flag: the repo builds with a module version in the advisory's range.
export const CANDIDATES = `
MATCH (r:Repo)-[:REQUIRES|BUILT_WITH]->(v:ModuleVersion)-[m:VULNERABLE_TO]->(a:Advisory)
RETURN r.name AS repo, r.sha AS sha, r.scanOk AS scanOk, r.scanExit AS scanExit, r.scanNote AS scanNote, r.module AS repoModule,
       r.scanDb AS scanDb, a.id AS advisory, a.published AS published, a.modified AS modified,
       a.addedAfterScan AS addedAfterScan,
       collect(v.path + '@' + v.version + '=>' + coalesce(m.fixed, '')) AS bumps
ORDER BY repo, advisory`;

// Affected = a call path through this repo's frames, from one of its entry points to a frame govulncheck
// reported as a vulnerable call, of a function this advisory names. shortestPath is a breadth-first
// search per (entry, target) pair, so the work stays small however much the chains branch; listing every
// path does not (it took a 100 MB FalkorDB Cloud instance down on net/http chains). The shortest path
// from shipped code is the evidence; failing that, the shortest one. Frames never cross repos.
export const CALL_PATH = `
MATCH (:Advisory {id: $advisory})-[:VULNERABLE_FUNC]->(:Func)<-[:IS]-(t:Frame {repo: $repo, vulnerable: true})
MATCH (:Repo {name: $repo})-[:ENTRY]->(e:Frame)
WITH e, shortestPath((e)-[:CALLS*1..30]->(t)) AS p
WHERE p IS NOT NULL
OPTIONAL MATCH (e)-[:DEFINED_IN]->(file:File)
WITH p, length(p) AS hops, file.path AS entryFile, reduce(s = '', n IN nodes(p) | s + n.func + ' ') AS sig
RETURN [n IN nodes(p) | n.func] AS path, [n IN nodes(p) | n.module] AS modules, entryFile, hops
ORDER BY hops, sig LIMIT 200`;

// Not affected, but imported: the vulnerable package is in the build and nothing reaches the bad code.
export const IMPORTED = `
MATCH (:Repo {name: $repo})-[:IMPORTS]->(p:Package)<-[:VULNERABLE_PACKAGE]-(:Advisory {id: $advisory})
RETURN p.path AS pkg LIMIT 1`;

const OWNER = `
MATCH (:Frame {key: $repo + '|' + $key})-[:DEFINED_IN]->(file:File)
OPTIONAL MATCH (file)-[:OWNED_BY]->(t:Team)
RETURN file.path AS file, collect(t.handle) AS owners LIMIT 1`;

export async function decide(c: Candidate): Promise<Decision> {
  const base = {
    repo: c.repo, advisory: c.advisory, bumps: [...c.bumps].sort(),
    path: [] as string[], callSite: null, file: null, owners: [] as string[], reach: null, entryFile: null, repoSha: c.sha,
    advisoryModified: c.modified, justification: null,
  };
  if (!c.scanOk) {
    return {
      ...base, status: "under_investigation",
      reason: `${c.bumps.map((b) => b.split("=>")[0]).join(", ")} in range, but the reachability scan of this commit failed (${c.scanNote ?? `exit ${c.scanExit ?? "none"}`}), so nothing is claimed`,
    };
  }
  // The scan only knew the advisories in its vulndb snapshot. A newer one has no call paths or imports
  // in the graph yet, so "no path" would prove nothing.
  if (scanPredates(c.scanDb, c.published) || c.addedAfterScan) {
    return {
      ...base, status: "under_investigation",
      reason: `${c.bumps.map((b) => b.split("=>")[0]).join(", ")} in range; the advisory was published after this commit was scanned (vulndb ${c.scanDb?.slice(0, 10)}), so it needs a rescan`,
    };
  }
  const paths = await read<{ path: string[]; modules: string[]; entryFile: string | null }>(CALL_PATH, {
    repo: c.repo, advisory: c.advisory,
  });
  const hit = paths.find((p) => isShipping(p.entryFile)) ?? paths[0];
  if (hit) {
    const shipped = isShipping(hit.entryFile);
    // Walk back from the vulnerable function to the first frame in the repo's own code: that is the
    // line that touches the dependency, and its CODEOWNERS team gets the work.
    let callSite: string | null = null;
    for (let i = hit.path.length - 1; i >= 0; i--) {
      if (hit.modules[i] === c.repoModule) {
        callSite = hit.path[i] ?? null;
        break;
      }
    }
    const [own] = callSite ? await read<{ file: string; owners: string[] }>(OWNER, { key: callSite, repo: c.repo }) : [];
    return {
      ...base, status: "affected", path: hit.path, callSite, file: own?.file ?? null, owners: own?.owners ?? [],
      reach: shipped ? "shipped" : "examples_tests_only", entryFile: hit.entryFile,
      reason: shipped
        ? `${hit.path.length - 1} call(s) from ${hit.path[0]} reach ${hit.path.at(-1)}`
        : `only reachable from ${hit.entryFile} (examples, tests or tooling), not from shipped code: ${hit.path.length - 1} call(s) reach ${hit.path.at(-1)}`,
    };
  }
  const [imp] = await read<{ pkg: string }>(IMPORTED, { repo: c.repo, advisory: c.advisory });
  if (imp) {
    return {
      ...base, status: "not_affected", justification: "vulnerable_code_not_in_execute_path",
      reason: `${imp.pkg} is imported, but no call path from this repo's code reaches the vulnerable functions`,
    };
  }
  return {
    ...base, status: "not_affected", justification: "vulnerable_code_not_present",
    reason: `${c.bumps.map((b) => b.split("=>")[0]).join(", ")} required, but no vulnerable package from it is imported`,
  };
}

export async function decideAll(): Promise<Decision[]> {
  const out: Decision[] = [];
  for (const c of await read<Candidate>(CANDIDATES)) out.push(await decide(c));
  return out;
}

const same = (a: Record<string, unknown>, d: Decision) =>
  // A null property is not stored, so it reads back as undefined.
  a.status === d.status && (a.justification ?? null) === d.justification && a.repoSha === d.repoSha &&
  a.advisoryModified === d.advisoryModified && JSON.stringify(a.path) === JSON.stringify(d.path) &&
  (a.reach ?? null) === d.reach;

// Stores decisions. Unchanged verdicts are kept; changed ones are superseded; verdicts whose pair is no
// longer flagged (the repo moved off the vulnerable version) are closed as "fixed".
export async function record(decisions: Decision[], now = new Date().toISOString()) {
  const current = new Map(
    (await read<{ key: string; v: Record<string, unknown> }>(
      `MATCH (v:Verdict {current: true}) RETURN v.key AS key, properties(v) AS v`,
    )).map((x) => [x.key, x.v]),
  );
  const fresh: (Decision & { key: string })[] = [];
  const reworded: { key: string; reason: string }[] = [];
  for (const d of decisions) {
    const key = `${d.repo}|${d.advisory}`;
    const prev = current.get(key);
    current.delete(key);
    if (!prev || !same(prev, d)) fresh.push({ ...d, key });
    // Same decision, clearer wording: not a new verdict, so the text is updated in place.
    else if (prev.reason !== d.reason) reworded.push({ key, reason: d.reason });
  }
  await write(
    `UNWIND $reworded AS x MATCH (v:Verdict {key: x.key, current: true}) SET v.reason = x.reason`,
    { reworded },
  );
  for (const [key, prev] of current) {
    if (prev.status === "fixed") continue;
    const [repo, advisory] = key.split("|") as [string, string];
    fresh.push({
      key, repo, advisory, status: "fixed", justification: null, bumps: (prev.bumps as string[]) ?? [], path: [],
      callSite: null, file: null, owners: [], reach: null, entryFile: null, repoSha: String(prev.repoSha),
      advisoryModified: String(prev.advisoryModified), reason: `no module version in the advisory's range is required any more`,
    });
  }
  await write(
    `UNWIND $fresh AS d
     MATCH (r:Repo {name: d.repo}), (a:Advisory {id: d.advisory})
     OPTIONAL MATCH (old:Verdict {key: d.key, current: true})
     SET old.current = false, old.supersededAt = $now
     CREATE (v:Verdict {key: d.key, current: true, decidedAt: $now, by: 'graph', status: d.status,
       justification: d.justification, bumps: d.bumps, path: d.path,
       callSite: d.callSite, file: d.file, owners: d.owners, reach: d.reach, entryFile: d.entryFile, repoSha: d.repoSha,
       advisoryModified: d.advisoryModified, reason: d.reason})
     CREATE (v)-[:FOR]->(r), (v)-[:ABOUT]->(a)
     FOREACH (_ IN CASE WHEN old IS NULL THEN [] ELSE [1] END | CREATE (v)-[:SUPERSEDES]->(old))
     WITH v, d
     UNWIND d.owners AS handle
     MATCH (t:Team {handle: handle})
     CREATE (v)-[:ROUTED_TO]->(t)`,
    { fresh, now },
  );
  return fresh.length;
}

if (import.meta.main) {
  const decisions = await decideAll();
  const changed = await record(decisions);
  const count = (f: (d: Decision) => boolean) => decisions.filter(f).length;
  console.log(`flagged by version: ${decisions.length} (repo, advisory) pairs across ${new Set(decisions.map((d) => d.repo)).size} repos`);
  console.log(`  affected (call path found)          ${count((d) => d.status === "affected")}`);
  console.log(`  not affected, imported but unreached ${count((d) => d.justification === "vulnerable_code_not_in_execute_path")}`);
  console.log(`  not affected, package not imported   ${count((d) => d.justification === "vulnerable_code_not_present")}`);
  console.log(`  under investigation (scan failed)    ${count((d) => d.status === "under_investigation")}`);
  console.log(`verdicts written: ${changed}`);
  await closeGraph();
}
