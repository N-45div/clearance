import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";
import { Hono } from "hono";
import { ask, type Turn } from "./agent.ts";
import { read } from "./db.ts";
import * as fleet from "./graph/fleet.ts";
import { issueDraft, vexDocument, type Frame, type VerdictRow } from "./report.ts";

const app = new Hono();
const api = new Hono();

api.get("/summary", async (c) => c.json(await fleet.summary()));
api.get("/advisories", async (c) => c.json(await fleet.advisories()));
api.get("/advisories/:id", async (c) => c.json(await fleet.blastRadius(c.req.param("id"))));
api.get("/repos", async (c) => c.json(await fleet.repos()));
api.get("/repos/:repo", async (c) => c.json(await fleet.repoVerdicts(c.req.param("repo"))));
api.get("/plan", async (c) => c.json(await fleet.fixPlan()));
api.get("/teams", async (c) => c.json(await fleet.teams()));

api.get("/evidence/:repo/:id", async (c) => {
  const ev = await fleet.evidence(c.req.param("repo"), c.req.param("id"));
  return ev ? c.json(ev) : c.json({ error: "no live verdict for that repo and advisory" }, 404);
});

const COLORS = {
  advisory: "#8E4EC6", module: "#8B8D98", team: "#3E63DD",
  affected: "#E5484D", not_affected: "#30A46C", under_investigation: "#F5A524",
};

// The advisory's neighbourhood for the canvas: Advisory <- module version <- repo -> owning team.
api.get("/graph/:id", async (c) => {
  const id = c.req.param("id");
  const rows = await read<{ repo: string; status: keyof typeof COLORS; mv: string; owners: string[] }>(
    `MATCH (v:Verdict {current: true})-[:ABOUT]->(a:Advisory {id: $id}), (v)-[:FOR]->(r:Repo)
     WHERE v.status <> 'fixed'
     MATCH (r)-[:REQUIRES|BUILT_WITH]->(mv:ModuleVersion)-[:VULNERABLE_TO]->(a)
     RETURN r.name AS repo, v.status AS status, mv.key AS mv, v.owners AS owners`,
    { id },
  );
  const nodes = new Map<string, { id: number; labels: string[]; color: string; visible: boolean; data: Record<string, string> }>();
  const links: { id: number; relationship: string; color: string; source: number; target: number; visible: boolean; data: object }[] = [];
  const node = (key: string, label: string, color: string, name: string, extra: Record<string, string> = {}) => {
    if (!nodes.has(key)) nodes.set(key, { id: nodes.size + 1, labels: [label], color, visible: true, data: { name, key, ...extra } });
    return nodes.get(key)!.id;
  };
  const link = (relationship: string, source: number, target: number) => {
    if (!links.some((l) => l.source === source && l.target === target && l.relationship === relationship)) {
      links.push({ id: links.length + 1, relationship, color: "#B9BBC6", source, target, visible: true, data: {} });
    }
  };
  const adv = node(`a:${id}`, "Advisory", COLORS.advisory, id);
  for (const r of rows) {
    const mv = node(`m:${r.mv}`, "ModuleVersion", COLORS.module, r.mv);
    const repo = node(`r:${r.repo}`, "Repo", COLORS[r.status], r.repo, { status: r.status });
    link("VULNERABLE_TO", mv, adv);
    link("REQUIRES", repo, mv);
    for (const t of r.owners ?? []) link("ROUTED_TO", repo, node(`t:${t}`, "Team", COLORS.team, t));
  }
  return c.json({ nodes: [...nodes.values()], links });
});

api.get("/vex/:repo", async (c) => {
  const repo = c.req.param("repo");
  const [r] = await read<{ org: string; sha: string; scanner: string | null }>(
    `MATCH (r:Repo {name: $repo}) RETURN r.org AS org, r.sha AS sha, r.scanner AS scanner`,
    { repo },
  );
  if (!r) return c.json({ error: "unknown repo" }, 404);
  const verdicts = await read<VerdictRow>(
    `MATCH (v:Verdict {current: true})-[:FOR]->(:Repo {name: $repo}), (v)-[:ABOUT]->(a:Advisory)
     RETURN a.id AS advisory, a.aliases AS aliases, v.status AS status, v.justification AS justification,
            v.reason AS reason, v.bumps AS bumps, v.reach AS reach
     ORDER BY a.id`,
    { repo },
  );
  const doc = vexDocument({ org: r.org, repo, sha: r.sha }, verdicts, new Date().toISOString(), `Clearance with govulncheck ${r.scanner ?? "(scan failed)"} call paths in FalkorDB`);
  c.header("Content-Disposition", `attachment; filename="${repo}.openvex.json"`);
  return c.json(doc);
});

api.get("/issue/:repo/:id", async (c) => {
  const repo = c.req.param("repo");
  const id = c.req.param("id");
  const ev = (await fleet.evidence(repo, id)) as
    | { v: Record<string, unknown>; sha: string; org: string; frames: Frame[] }
    | undefined;
  if (!ev || ev.v.status !== "affected") return c.json({ error: "issue drafts are only for affected verdicts" }, 404);
  const adv = (await fleet.advisory(id)) as { id: string; summary: string; url: string; aliases: string[] };
  const [scan] = await read<{ scanner: string; go: string }>(
    `MATCH (r:Repo {name: $repo}) RETURN r.scanner AS scanner, r.scanToolchain AS go`,
    { repo },
  );
  return c.json(
    issueDraft({
      ref: { org: ev.org, repo, sha: ev.sha },
      advisory: adv,
      bumps: ev.v.bumps as string[],
      frames: ev.frames,
      owners: (ev.v.owners as string[]) ?? [],
      decidedAt: String(ev.v.decidedAt),
      scanner: `govulncheck ${scan?.scanner ?? ""} with ${scan?.go ?? "the declared toolchain"}`,
    }),
  );
});

api.post("/ask", async (c) => {
  const body = await c.req.json<{ question?: string; history?: Turn[] }>();
  const question = body.question?.trim();
  if (!question) return c.json({ error: "question is required" }, 400);
  if (question.length > 2000) return c.json({ error: "question is too long" }, 400);
  try {
    return c.json(await ask(question, body.history ?? []));
  } catch (e) {
    return c.json({ error: (e as Error).message }, 502);
  }
});

app.route("/api", api);
app.onError((err, c) => c.json({ error: err.message }, 500));
app.use("/*", serveStatic({ root: "./web/dist" }));
app.get("/*", serveStatic({ path: "./web/dist/index.html" }));

const port = Number(process.env.PORT ?? 8080);
serve({ fetch: app.fetch, port }, () => console.log(`Clearance on http://localhost:${port}`));
