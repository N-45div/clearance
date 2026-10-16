import { Hono } from "hono";
import { ask, type Turn } from "./agent.ts";
import { read } from "./db.ts";
import * as fleet from "./graph/fleet.ts";
import { waitUntil } from "@vercel/functions";
import { checkFeed } from "./ingest/feed.ts";
import { isMissingGraph, rebuilding, reloadIfEmpty } from "./graph/reload.ts";
import { allowAsk, allowMcp, clientIp } from "./limits.ts";
import { handle as handleMcp } from "./mcp.ts";
import { issueDraft, vexDocument, type Frame, type VerdictRow } from "./report.ts";

const app = new Hono();
const api = new Hono();

const REBUILDING = "The graph is being rebuilt (the free FalkorDB Cloud instance restarted). Try again in a minute.";

// While a rebuild runs the graph is half-built; say so instead of answering from it.
api.use("*", async (c, next) => {
  if (!c.req.path.startsWith("/api/cron/") && (await rebuilding())) return c.json({ error: REBUILDING, rebuilding: true }, 503);
  await next();
});

api.get("/summary", async (c) => c.json(await fleet.summary()));
api.get("/advisories", async (c) => c.json(await fleet.advisories()));
api.get("/advisories/:id", async (c) => c.json(await fleet.blastRadius(c.req.param("id"))));
api.get("/repos", async (c) => c.json(await fleet.repos()));
api.get("/repos/:repo", async (c) => c.json(await fleet.repoVerdicts(c.req.param("repo"))));
api.get("/plan", async (c) => c.json(await fleet.fixPlan()));
api.get("/teams", async (c) => c.json(await fleet.teams()));
api.get("/changes", async (c) => c.json(await fleet.changes()));

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
  const [r] = await read<{ org: string; sha: string; module: string | null; scanner: string | null }>(
    `MATCH (r:Repo {name: $repo}) RETURN r.org AS org, r.sha AS sha, r.module AS module, r.scanner AS scanner`,
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
  const doc = vexDocument({ org: r.org, repo, sha: r.sha, module: r.module }, verdicts, new Date().toISOString(), `Clearance with govulncheck ${r.scanner ?? "(scan failed)"} call paths in FalkorDB`);
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
  const limit = await allowAsk(clientIp(c.req.raw.headers));
  if (!limit.ok) {
    c.header("Retry-After", String(limit.retryAfter));
    return c.json({ error: `Limit reached: ${limit.reason}. Everything else in the app still works.` }, 429);
  }
  // Only well-formed, short turns go back to the model.
  const history = (Array.isArray(body.history) ? body.history : [])
    .filter((t) => (t?.role === "user" || t?.role === "assistant") && typeof t.content === "string")
    .slice(-6)
    .map((t) => ({ role: t.role, content: t.content.slice(0, 4000) }));
  try {
    return c.json(await ask(question, history));
  } catch (e) {
    return c.json({ error: (e as Error).message }, 502);
  }
});

// MCP over Streamable HTTP. Stateless: no session id, no server-sent events, so GET has nothing to stream.
api.get("/mcp", (c) => c.json({ error: "POST JSON-RPC messages to this endpoint" }, 405, { Allow: "POST" }));
api.post("/mcp", async (c) => {
  const limit = await allowMcp(clientIp(c.req.raw.headers));
  if (!limit.ok) {
    c.header("Retry-After", String(limit.retryAfter));
    return c.json({ jsonrpc: "2.0", id: null, error: { code: -32000, message: `Limit reached: ${limit.reason}` } }, 429);
  }
  let msg: unknown;
  try {
    msg = await c.req.json();
  } catch {
    return c.json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } }, 400);
  }
  if (Array.isArray(msg)) return c.json({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "batches are not supported" } }, 400);
  const reply = await handleMcp(msg as Parameters<typeof handleMcp>[0]);
  return reply ? c.json(reply) : c.body(null, 202);
});

// Vercel calls this once a day: it rebuilds the graph if the free FalkorDB Cloud instance came back
// empty, keeps the instance in use (it stops after a day idle), and loads any new Go advisory that
// touches the fleet. It writes, so it needs CRON_SECRET.
api.get("/cron/daily", async (c) => {
  const secret = process.env.CRON_SECRET;
  if (!secret) return c.json({ error: "CRON_SECRET is not set" }, 503);
  if (c.req.header("authorization") !== `Bearer ${secret}`) return c.json({ error: "unauthorized" }, 401);
  const reload = await reloadIfEmpty();
  const [r] = await read<{ repos: number }>(`MATCH (r:Repo) RETURN count(r) AS repos`);
  const feed = await checkFeed();
  return c.json({ ok: true, reload, repos: r?.repos ?? 0, feed, at: new Date().toISOString() });
});

app.route("/api", api);
// The web app is static (public/, served by the CDN); its entry page is index.html.
app.get("/", (c) => c.redirect("/index.html"));
app.onError((err, c) => {
  // The graph is gone (a free instance restarted): start one rebuild in the background and say so.
  if (isMissingGraph(err)) {
    const rebuild = reloadIfEmpty().catch((e: Error) => console.error(`reload failed: ${e.message}`));
    try {
      waitUntil(rebuild);
    } catch {
      void rebuild;
    }
    return c.json({ error: REBUILDING, rebuilding: true }, 503);
  }
  return c.json({ error: err.message }, 500);
});

// Vercel runs this default export as a function; src/main.ts runs it locally.
export default app;
