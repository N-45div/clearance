// Writes the fleet into FalkorDB. Every loader is idempotent: re-running ingest replaces a repo's
// facts with the ones at its current pinned commit.
import { write } from "../db.ts";
import { ownersFor, parseCodeowners, type OwnerRule } from "../ingest/codeowners.ts";
import { rawFile } from "../ingest/github.ts";
import { parseGoMod, stdlibVersion, type GoMod } from "../ingest/gomod.ts";
import type { GoAdvisory, Pair } from "../ingest/osv.ts";
import type { FleetLock } from "../ingest/pin.ts";
import { callFacts, funcKey, repoPath, type Frame, type Scan } from "../ingest/scans.ts";
import { fixedAfter } from "../ingest/semver.ts";

const key = (p: Pair) => `${p.path}@${p.version}`;

export type RepoData = { name: string; mod: GoMod; stdlib: string | undefined; rules: OwnerRule[] };

export async function readRepos(lock: FleetLock): Promise<RepoData[]> {
  const out: RepoData[] = [];
  for (const pin of lock.repos) {
    const text = await rawFile(lock.org, pin.repo, pin.sha, "go.mod");
    if (!text) throw new Error(`${pin.repo}: no go.mod at ${pin.sha}`);
    const mod = parseGoMod(text);
    const owners = pin.owners ? await rawFile(lock.org, pin.repo, pin.sha, pin.owners) : undefined;
    out.push({ name: pin.repo, mod, stdlib: stdlibVersion(mod), rules: owners ? parseCodeowners(owners) : [] });
  }
  return out;
}

export async function loadRepos(lock: FleetLock, repos: RepoData[]) {
  await write(
    `UNWIND $repos AS r
     MERGE (x:Repo {name: r.name})
     SET x.org = r.org, x.sha = r.sha, x.branch = r.branch, x.committedAt = r.committedAt,
         x.module = r.module, x.stdlib = r.stdlib, x.url = r.url
     WITH x
     OPTIONAL MATCH (x)-[e:REQUIRES|BUILT_WITH]->()
     DELETE e`,
    {
      repos: lock.repos.map((p) => {
        const d = repos.find((r) => r.name === p.repo)!;
        return {
          name: p.repo, org: lock.org, sha: p.sha, branch: p.branch, committedAt: p.committedAt,
          module: d.mod.module, stdlib: d.stdlib ?? null, url: `https://github.com/${lock.org}/${p.repo}/tree/${p.sha}`,
        };
      }),
    },
  );

  const versions = new Map<string, Pair>();
  const requires: { repo: string; key: string; direct: boolean }[] = [];
  for (const r of repos) {
    for (const q of r.mod.requires) {
      versions.set(key(q), { path: q.path, version: q.version });
      requires.push({ repo: r.name, key: key(q), direct: q.direct });
    }
    if (r.stdlib) versions.set(key({ path: "stdlib", version: r.stdlib }), { path: "stdlib", version: r.stdlib });
  }
  await write(
    `UNWIND $mvs AS mv
     MERGE (m:Module {path: mv.path})
     MERGE (v:ModuleVersion {key: mv.key})
     ON CREATE SET v.path = mv.path, v.version = mv.version
     MERGE (v)-[:OF]->(m)`,
    { mvs: [...versions.entries()].map(([k, p]) => ({ key: k, ...p })) },
  );
  await write(
    `UNWIND $reqs AS q
     MATCH (r:Repo {name: q.repo}), (v:ModuleVersion {key: q.key})
     CREATE (r)-[:REQUIRES {direct: q.direct}]->(v)`,
    { reqs: requires },
  );
  await write(
    `UNWIND $built AS b
     MATCH (r:Repo {name: b.repo}), (v:ModuleVersion {key: b.key})
     CREATE (r)-[:BUILT_WITH]->(v)`,
    { built: repos.filter((r) => r.stdlib).map((r) => ({ repo: r.name, key: `stdlib@${r.stdlib}` })) },
  );
  return [...versions.values()];
}

export async function loadOwners(repos: RepoData[]) {
  await write(`MATCH (o:OwnerRule) DETACH DELETE o`);
  const rules = repos.flatMap((r) =>
    r.rules.filter((x) => x.teams.length).map((x) => ({ repo: r.name, pattern: x.pattern, order: x.order, teams: x.teams })),
  );
  await write(
    `UNWIND $rules AS x
     MATCH (r:Repo {name: x.repo})
     CREATE (r)-[:HAS_RULE]->(o:OwnerRule {repo: x.repo, pattern: x.pattern, order: x.order})
     WITH o, x
     UNWIND x.teams AS handle
     MERGE (t:Team {handle: handle})
     CREATE (o)-[:ASSIGNS]->(t)`,
    { rules },
  );
  return rules.length;
}

export async function loadAdvisories(advisories: GoAdvisory[]) {
  await write(
    `UNWIND $advs AS a
     MERGE (x:Advisory {id: a.id})
     SET x.summary = a.summary, x.published = a.published, x.modified = a.modified,
         x.aliases = a.aliases, x.url = 'https://pkg.go.dev/vuln/' + a.id`,
    { advs: advisories.map(({ affected: _, ...a }) => a) },
  );
  const affects = advisories.flatMap((a) =>
    a.affected.map((f) => ({ id: a.id, module: f.module, fixed: f.events.flatMap((e) => (e.fixed ? [e.fixed] : [])) })),
  );
  await write(
    `UNWIND $affects AS f
     MATCH (a:Advisory {id: f.id})
     MERGE (m:Module {path: f.module})
     MERGE (a)-[e:AFFECTS]->(m)
     SET e.fixed = f.fixed`,
    { affects },
  );
  const funcs = advisories.flatMap((a) =>
    a.affected.flatMap((f) =>
      f.imports.flatMap((imp) =>
        imp.symbols.map((s) => ({ id: a.id, module: f.module, pkg: imp.path, name: s, key: `${imp.path}.${s}` })),
      ),
    ),
  );
  const packages = advisories.flatMap((a) =>
    a.affected.flatMap((f) => f.imports.map((imp) => ({ id: a.id, module: f.module, pkg: imp.path }))),
  );
  await write(
    `UNWIND $packages AS p
     MATCH (a:Advisory {id: p.id})
     MERGE (m:Module {path: p.module})
     MERGE (pkg:Package {path: p.pkg})
     MERGE (pkg)-[:IN]->(m)
     MERGE (a)-[:VULNERABLE_PACKAGE]->(pkg)`,
    { packages },
  );
  for (let i = 0; i < funcs.length; i += 2000) {
    await write(
      `UNWIND $funcs AS f
       MATCH (a:Advisory {id: f.id}), (pkg:Package {path: f.pkg})
       MERGE (fn:Func {key: f.key})
       ON CREATE SET fn.package = f.pkg, fn.name = f.name
       SET fn.module = f.module
       MERGE (fn)-[:IN]->(pkg)
       MERGE (a)-[:VULNERABLE_FUNC]->(fn)`,
      { funcs: funcs.slice(i, i + 2000) },
    );
  }
  return funcs.length;
}

// A full ingest replaces every match; the advisory feed replaces only the advisories it just loaded.
export async function loadMatches(hits: Map<string, string[]>, advisories: Map<string, GoAdvisory>, only?: string[]) {
  if (only) await write(`MATCH ()-[e:VULNERABLE_TO]->(a:Advisory) WHERE a.id IN $only DELETE e`, { only });
  else await write(`MATCH ()-[e:VULNERABLE_TO]->() DELETE e`);
  const edges: { key: string; id: string; fixed: string | null }[] = [];
  for (const [k, ids] of hits) {
    const at = k.lastIndexOf("@");
    const path = k.slice(0, at);
    const version = k.slice(at + 1);
    for (const id of ids) {
      const adv = advisories.get(id);
      if (!adv) continue;
      const events = adv.affected.filter((f) => f.module === path).flatMap((f) => f.events);
      edges.push({ key: k, id, fixed: fixedAfter(version, events) ?? null });
    }
  }
  await write(
    `UNWIND $edges AS x
     MATCH (v:ModuleVersion {key: x.key}), (a:Advisory {id: x.id})
     CREATE (v)-[:VULNERABLE_TO {fixed: x.fixed}]->(a)`,
    { edges },
  );
  return edges.length;
}

export type ScanStatus = { repo: string; ok: boolean; exit: number; toolchain: string; note: string | null };

// Repo-scoped facts from govulncheck: IMPORTS, ENTRY, CALLS {repo}, and for frames in the repo's own
// code, the file and the CODEOWNERS team that owns it.
export async function loadScan(repo: RepoData, status: ScanStatus, scan: Scan | undefined) {
  await write(
    `MATCH (r:Repo {name: $repo})
     SET r.scanOk = $ok, r.scanExit = $exit, r.scanToolchain = $toolchain,
         r.scanner = $scanner, r.scanDb = $db, r.scanNote = $note
     WITH r
     OPTIONAL MATCH (r)-[e:IMPORTS|ENTRY]->()
     DELETE e`,
    {
      repo: repo.name, ok: status.ok && !!scan?.config, exit: status.exit, toolchain: status.toolchain, note: status.note,
      scanner: scan?.config?.scanner_version ?? null, db: scan?.config?.db_last_modified ?? null,
    },
  );
  await write(`MATCH ()-[c:CALLS {repo: $repo}]->() DELETE c`, { repo: repo.name });
  await write(`MATCH (f:File {repo: $repo}) DETACH DELETE f`, { repo: repo.name });
  if (!scan || !status.ok) return { imports: 0, calls: 0, entries: 0, files: 0 };

  const facts = callFacts(scan);
  const node = (fr: Frame) => ({
    key: funcKey(fr), pkg: fr.package ?? "", name: funcKey(fr).slice((fr.package ?? "").length + 1),
    module: fr.module, path: repoPath(fr, repo.mod.module) ?? null,
    line: fr.position?.line ?? null,
  });
  const calls = [...facts.calls.values()].map((c) => ({ from: node(c.from), to: node(c.to) }));
  const entries = [...facts.entries.values()].map(node);

  await write(
    `UNWIND $pkgs AS p
     MATCH (r:Repo {name: $repo})
     MERGE (pkg:Package {path: p})
     MERGE (r)-[:IMPORTS]->(pkg)`,
    { repo: repo.name, pkgs: [...facts.imports] },
  );
  for (let i = 0; i < calls.length; i += 2000) {
    await write(
      `UNWIND $calls AS c
       MERGE (a:Func {key: c.from.key})
       ON CREATE SET a.package = c.from.pkg, a.name = c.from.name
       SET a.module = c.from.module
       MERGE (b:Func {key: c.to.key})
       ON CREATE SET b.package = c.to.pkg, b.name = c.to.name
       SET b.module = c.to.module
       MERGE (a)-[:CALLS {repo: $repo}]->(b)`,
      { repo: repo.name, calls: calls.slice(i, i + 2000) },
    );
  }
  await write(
    `UNWIND $entries AS e
     MATCH (r:Repo {name: $repo}), (f:Func {key: e.key})
     MERGE (r)-[:ENTRY]->(f)`,
    { repo: repo.name, entries },
  );

  // Frames in the repo's own code carry a file and line; CODEOWNERS turns the file into a team.
  const own = new Map<string, { key: string; path: string; line: number; teams: string[] }>();
  for (const fr of [...calls.flatMap((c) => [c.from, c.to]), ...entries]) {
    if (!fr.path || own.has(fr.key)) continue;
    own.set(fr.key, { key: fr.key, path: fr.path, line: fr.line ?? 0, teams: ownersFor(repo.rules, fr.path)?.teams ?? [] });
  }
  await write(
    `UNWIND $own AS o
     MATCH (fn:Func {key: o.key})
     MERGE (file:File {key: $repo + ':' + o.path})
     ON CREATE SET file.repo = $repo, file.path = o.path
     MERGE (fn)-[d:DEFINED_IN]->(file)
     SET d.line = o.line
     WITH file, o
     UNWIND o.teams AS handle
     MERGE (t:Team {handle: handle})
     MERGE (file)-[:OWNED_BY]->(t)`,
    { repo: repo.name, own: [...own.values()] },
  );
  return { imports: facts.imports.size, calls: calls.length, entries: entries.length, files: own.size };
}
