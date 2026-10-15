// Writes the fleet into FalkorDB. Every loader is idempotent: re-running ingest replaces a repo's
// facts with the ones at its current pinned commit.
import { write } from "../db.ts";
import { parseCodeowners, type OwnerRule } from "../ingest/codeowners.ts";
import { rawFile } from "../ingest/github.ts";
import { parseGoMod, stdlibVersion, type GoMod } from "../ingest/gomod.ts";
import type { GoAdvisory, Pair } from "../ingest/osv.ts";
import type { FleetLock } from "../ingest/pin.ts";
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
       MERGE (fn)-[:IN]->(pkg)
       MERGE (a)-[:VULNERABLE_FUNC]->(fn)`,
      { funcs: funcs.slice(i, i + 2000) },
    );
  }
  return funcs.length;
}

export async function loadMatches(hits: Map<string, string[]>, advisories: Map<string, GoAdvisory>) {
  await write(`MATCH ()-[e:VULNERABLE_TO]->() DELETE e`);
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
