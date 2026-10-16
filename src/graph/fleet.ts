// Read-only questions about the fleet. The API and the agent's tools both call these, so every answer
// the agent gives comes from the same Cypher a person can run in the FalkorDB Browser.
import { read } from "../db.ts";
import { compare } from "../ingest/semver.ts";

const STATUS_COUNTS = `
  sum(CASE WHEN v.status = 'affected' THEN 1 ELSE 0 END) AS affected,
  sum(CASE WHEN v.status = 'not_affected' THEN 1 ELSE 0 END) AS notAffected,
  sum(CASE WHEN v.status = 'under_investigation' THEN 1 ELSE 0 END) AS underInvestigation`;

export type Bump = { module: string; from: string; to: string | null };

export function parseBump(b: string): Bump {
  const [left = "", to = ""] = b.split("=>");
  const at = left.lastIndexOf("@");
  return { module: left.slice(0, at), from: left.slice(at + 1), to: to || null };
}

export async function summary() {
  const [v] = await read<Record<string, number>>(
    `MATCH (v:Verdict {current: true}) WHERE v.status <> 'fixed'
     RETURN count(v) AS flagged, ${STATUS_COUNTS}`,
  );
  const [r] = await read<{ repos: number; scanned: number; pinnedAt: string }>(
    `MATCH (r:Repo) RETURN count(r) AS repos, sum(CASE WHEN r.scanOk THEN 1 ELSE 0 END) AS scanned`,
  );
  const [a] = await read<{ advisories: number }>(
    `MATCH (v:Verdict {current: true})-[:ABOUT]->(a:Advisory) WHERE v.status <> 'fixed' RETURN count(DISTINCT a) AS advisories`,
  );
  const plan = await fixPlan();
  return {
    ...v, ...r, ...a,
    pullRequests: plan.length,
    teams: new Set(plan.flatMap((p) => p.teams)).size,
  };
}

export async function advisories() {
  return read(
    // Aggregate on the node, then project: on FalkorDB 6.0.2, grouping on four keys where one is a
    // list makes every sum(CASE ...) return count() instead.
    `MATCH (v:Verdict {current: true})-[:ABOUT]->(a:Advisory) WHERE v.status <> 'fixed'
     WITH a, count(v) AS repos, ${STATUS_COUNTS}
     RETURN a.id AS id, a.summary AS summary, a.published AS published, a.aliases AS aliases,
            repos, affected, notAffected, underInvestigation
     ORDER BY published DESC, id DESC`,
  );
}

export async function advisory(id: string) {
  const [a] = await read(
    `MATCH (a:Advisory {id: $id})
     OPTIONAL MATCH (a)-[e:AFFECTS]->(m:Module)
     RETURN a.id AS id, a.summary AS summary, a.published AS published, a.modified AS modified,
            a.aliases AS aliases, a.url AS url, collect({module: m.path, fixed: e.fixed}) AS modules`,
    { id },
  );
  return a;
}

// Every repo the advisory's version range reaches, and what the graph decided for each.
export async function blastRadius(id: string) {
  const repos = await read(
    `MATCH (v:Verdict {current: true})-[:ABOUT]->(:Advisory {id: $id}), (v)-[:FOR]->(r:Repo)
     WHERE v.status <> 'fixed'
     RETURN r.name AS repo, r.sha AS sha, v.status AS status, v.justification AS justification,
            v.reason AS reason, v.path AS path, v.callSite AS callSite, v.file AS file,
            v.owners AS owners, v.bumps AS bumps, v.reach AS reach, v.entryFile AS entryFile, v.decidedAt AS decidedAt
     ORDER BY CASE v.status WHEN 'affected' THEN 0 WHEN 'under_investigation' THEN 1 ELSE 2 END, repo`,
    { id },
  );
  const count = (s: string) => repos.filter((r) => r.status === s).length;
  return {
    advisory: await advisory(id),
    counts: {
      flagged: repos.length, affected: count("affected"), notAffected: count("not_affected"),
      underInvestigation: count("under_investigation"),
      examplesTestsOnly: repos.filter((r) => r.reach === "examples_tests_only").length,
    },
    repos,
  };
}

// The call path behind one verdict, frame by frame, with file, line and owning team for the repo's own code.
export async function evidence(repo: string, id: string) {
  const key = `${repo}|${id}`;
  const [verdict] = await read<Record<string, unknown>>(
    `MATCH (v:Verdict {key: $key, current: true})-[:FOR]->(r:Repo)
     RETURN properties(v) AS v, r.sha AS sha, r.org AS org, r.module AS module`,
    { key },
  );
  if (!verdict) return undefined;
  const frames = await read(
    `MATCH (v:Verdict {key: $key, current: true})
     UNWIND range(0, size(v.path) - 1) AS i
     MATCH (f:Frame {key: $repo + '|' + v.path[i]})
     OPTIONAL MATCH (f)-[d:DEFINED_IN]->(file:File)
     OPTIONAL MATCH (file)-[:OWNED_BY]->(t:Team)
     RETURN i, f.func AS key, f.name AS name, f.package AS package, f.module AS module,
            file.path AS file, d.line AS line, collect(t.handle) AS owners
     ORDER BY i`,
    { key, repo },
  );
  const history = await read(
    `MATCH (v:Verdict {key: $key})
     RETURN v.status AS status, v.justification AS justification, v.decidedAt AS decidedAt,
            v.supersededAt AS supersededAt, v.repoSha AS repoSha, v.current AS current
     ORDER BY v.decidedAt DESC`,
    { key },
  );
  return { ...verdict, frames, history };
}

export type PlannedFix = {
  repo: string;
  module: string;
  from: string;
  to: string | null;
  advisories: string[];
  teams: string[];
};

// One pull request per (repo, module): bump to the highest fix any affected advisory needs.
export async function fixPlan(): Promise<PlannedFix[]> {
  const rows = await read<{ repo: string; bump: string; advisory: string; owners: string[] }>(
    `MATCH (v:Verdict {current: true, status: 'affected'})-[:FOR]->(r:Repo), (v)-[:ABOUT]->(a:Advisory)
     UNWIND v.bumps AS bump
     RETURN r.name AS repo, bump, a.id AS advisory, v.owners AS owners`,
  );
  const plan = new Map<string, PlannedFix>();
  for (const row of rows) {
    const b = parseBump(row.bump);
    const k = `${row.repo}|${b.module}`;
    const p = plan.get(k) ?? { repo: row.repo, module: b.module, from: b.from, to: null, advisories: [], teams: [] };
    if (b.to && (!p.to || compare(b.to, p.to) > 0)) p.to = b.to;
    if (!p.advisories.includes(row.advisory)) p.advisories.push(row.advisory);
    for (const t of row.owners ?? []) if (!p.teams.includes(t)) p.teams.push(t);
    plan.set(k, p);
  }
  return [...plan.values()].sort((a, b) => b.advisories.length - a.advisories.length || a.repo.localeCompare(b.repo));
}

// Affected work per CODEOWNERS team; verdicts whose call site has no team are listed as unowned.
export async function teams() {
  const owned = await read(
    `MATCH (v:Verdict {current: true, status: 'affected'})-[:ROUTED_TO]->(t:Team), (v)-[:FOR]->(r:Repo)
     RETURN t.handle AS team, count(v) AS verdicts, collect(DISTINCT r.name) AS repos
     ORDER BY verdicts DESC`,
  );
  const [unowned] = await read<{ verdicts: number; repos: string[] }>(
    `MATCH (v:Verdict {current: true, status: 'affected'})-[:FOR]->(r:Repo)
     WHERE NOT (v)-[:ROUTED_TO]->(:Team)
     RETURN count(v) AS verdicts, collect(DISTINCT r.name) AS repos`,
  );
  return { owned, unowned };
}

export async function repos() {
  return read(
    `MATCH (r:Repo)
     OPTIONAL MATCH (v:Verdict {current: true})-[:FOR]->(r) WHERE v.status <> 'fixed'
     RETURN r.name AS repo, r.sha AS sha, r.stdlib AS go, r.scanOk AS scanOk, r.scanNote AS scanNote,
            count(v) AS flagged, ${STATUS_COUNTS}
     ORDER BY affected DESC, flagged DESC, repo`,
  );
}

export async function repoVerdicts(repo: string) {
  return read(
    `MATCH (v:Verdict {current: true})-[:FOR]->(:Repo {name: $repo}), (v)-[:ABOUT]->(a:Advisory)
     WHERE v.status <> 'fixed'
     RETURN a.id AS advisory, a.summary AS summary, v.status AS status, v.justification AS justification,
            v.reason AS reason, v.callSite AS callSite, v.file AS file, v.owners AS owners, v.bumps AS bumps,
            v.reach AS reach
     ORDER BY CASE v.status WHEN 'affected' THEN 0 WHEN 'under_investigation' THEN 1 ELSE 2 END, a.id`,
    { repo },
  );
}

// Where each repo's own code calls into a package (prefix match), with file:line and owning team.
export async function callSites(pkg: string) {
  return read(
    `MATCH (c:Frame)-[:CALLS]->(d:Frame) WHERE d.package STARTS WITH $pkg
     MATCH (c)-[l:DEFINED_IN]->(file:File)
     OPTIONAL MATCH (file)-[:OWNED_BY]->(t:Team)
     RETURN c.repo AS repo, file.path AS file, l.line AS line, c.name AS caller,
            collect(DISTINCT d.package + '.' + d.name) AS calls, collect(DISTINCT t.handle) AS teams
     ORDER BY repo, file, line`,
    { pkg },
  );
}

// What the graph re-decided and why: every live verdict that superseded an older one, newest first.
export async function changes(limit = 200) {
  return read(
    `MATCH (n:Verdict {current: true})-[:SUPERSEDES]->(o:Verdict), (n)-[:FOR]->(r:Repo), (n)-[:ABOUT]->(a:Advisory)
     RETURN r.name AS repo, a.id AS advisory, a.summary AS summary, o.status AS fromStatus, n.status AS toStatus,
            o.repoSha AS fromSha, n.repoSha AS toSha, o.decidedAt AS fromAt, n.decidedAt AS at, n.reason AS reason
     ORDER BY at DESC, repo, advisory
     LIMIT $limit`,
    { limit },
  );
}
