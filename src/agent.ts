// The triage agent. It answers questions about the fleet by choosing graph tools; it never decides a
// verdict (those are already in the graph) and it never holds database credentials: every tool is a
// fixed read-only query, and run_cypher goes through GRAPH.RO_QUERY with a row cap.
import { read } from "./db.ts";
import * as fleet from "./graph/fleet.ts";

type Tool = {
  description: string;
  parameters: Record<string, unknown>;
  run: (args: Record<string, string>) => Promise<unknown>;
};

const str = (description: string) => ({ type: "string", description });
const obj = (props: Record<string, unknown>, required: string[] = []) => ({
  type: "object", properties: props, required, additionalProperties: false,
});

export const SCHEMA = `Nodes: Repo{name,sha,module,stdlib,scanOk,scanNote}, Module{path}, ModuleVersion{key,path,version},
Advisory{id,summary,published,modified,aliases,url}, Package{path}, Func{key,package,name,module}, File{repo,path},
Team{handle}, OwnerRule{pattern}, Verdict{key,current,status,justification,reason,path,callSite,file,owners,bumps,decidedAt,supersededAt}.
Edges: (Repo)-[:REQUIRES {direct}]->(ModuleVersion)-[:OF]->(Module); (Repo)-[:BUILT_WITH]->(ModuleVersion {path:'stdlib'});
(ModuleVersion)-[:VULNERABLE_TO {fixed}]->(Advisory)-[:AFFECTS {fixed}]->(Module); (Advisory)-[:VULNERABLE_FUNC]->(Func);
(Advisory)-[:VULNERABLE_PACKAGE]->(Package); (Repo)-[:IMPORTS]->(Package); (Repo)-[:ENTRY]->(Func);
(Func)-[:CALLS {repo}]->(Func); (Func)-[:DEFINED_IN {line}]->(File)-[:OWNED_BY]->(Team);
(Verdict)-[:FOR]->(Repo), (Verdict)-[:ABOUT]->(Advisory), (Verdict)-[:ROUTED_TO]->(Team), (Verdict)-[:SUPERSEDES]->(Verdict).
Verdict.status: affected | not_affected | under_investigation | fixed. Only current:true verdicts are live.
CALLS edges exist only on paths toward vulnerable functions (they are govulncheck evidence, not a full call graph).
DEFINED_IN exists only for functions in a repo's own code (the callers), never for dependency functions.
Examples:
- repos' own call sites into a package: MATCH (c:Func)-[k:CALLS]->(d:Func) WHERE d.package STARTS WITH 'golang.org/x/net/http2' MATCH (c)-[l:DEFINED_IN]->(f:File {repo: k.repo}) RETURN k.repo, f.path, l.line
- live verdicts a team must act on: MATCH (v:Verdict {current: true, status: 'affected'})-[:ROUTED_TO]->(:Team {handle: '@grafana/k6-core'}) RETURN v.key, v.file`;

export const TOOLS: Record<string, Tool> = {
  fleet_summary: {
    description: "Counts for the whole fleet: flagged (repo, advisory) pairs, affected, not affected, under investigation, pull requests needed, teams.",
    parameters: obj({}),
    run: () => fleet.summary(),
  },
  list_advisories: {
    description: "Every advisory that reaches the fleet, newest first, with how many repos are affected / not affected / under investigation.",
    parameters: obj({}),
    run: () => fleet.advisories(),
  },
  blast_radius: {
    description: "For one advisory (e.g. GO-2026-6609): every repo its version range reaches and the verdict for each, with call site, owners and fix.",
    parameters: obj({ advisory: str("Go vulndb id, e.g. GO-2026-6609") }, ["advisory"]),
    run: (a) => fleet.blastRadius(a.advisory ?? ""),
  },
  evidence: {
    description: "The call path behind one repo's verdict on one advisory, frame by frame, with file:line and owning team, plus the verdict history.",
    parameters: obj({ repo: str("repo name, e.g. k6"), advisory: str("advisory id") }, ["repo", "advisory"]),
    run: (a) => fleet.evidence(a.repo ?? "", a.advisory ?? ""),
  },
  repo_verdicts: {
    description: "All live verdicts for one repo.",
    parameters: obj({ repo: str("repo name") }, ["repo"]),
    run: (a) => fleet.repoVerdicts(a.repo ?? ""),
  },
  fix_plan: {
    description: "The pull requests that close every affected verdict: one per (repo, module), the version to bump to, the advisories it closes, and the owning teams.",
    parameters: obj({}),
    run: () => fleet.fixPlan(),
  },
  team_inbox: {
    description: "Affected verdicts per CODEOWNERS team, and how many have no owning team.",
    parameters: obj({}),
    run: () => fleet.teams(),
  },
  call_sites: {
    description: "Where each repo's own code calls into a package (prefix match, e.g. golang.org/x/net/http2), with file:line and owning team. Only calls on paths toward vulnerable code are known.",
    parameters: obj({ package: str("Go package path or prefix") }, ["package"]),
    run: (a) => fleet.callSites(a.package ?? ""),
  },
  run_cypher: {
    description: `Run one read-only Cypher query on the FalkorDB graph when no other tool answers the question. Use $-free literal queries, return at most 50 rows. Schema:\n${SCHEMA}`,
    parameters: obj({ cypher: str("a read-only Cypher query") }, ["cypher"]),
    // A model-written query gets 5 s; FalkorDB aborts it after that.
    run: async (a) => (await read(a.cypher ?? "", {}, 5_000)).slice(0, 50),
  },
};

const SYSTEM = `You are Clearance, a triage assistant for a fleet of Go services. Every verdict lives in a FalkorDB graph and was decided from call paths found by govulncheck, not by you.
Rules:
- Answer only from tool results. If the graph has no answer, say so.
- When you say a repo is affected, name the call site (file:line if known) and the owning team. When you say not affected, give the justification.
- "under_investigation" means the reachability scan failed; never present it as safe.
- reach "examples_tests_only" means the only path starts in examples, tests or tooling (entryFile), not in shipped code: say so, and call it lower priority.
- Use the counts the tools return; do not recount.
- Standard-library verdicts assume the Go toolchain declared in the repo's go.mod.
- Be brief: short sentences, plain words, lists for several repos.`;

export type Step = { tool: string; args: Record<string, string>; rows: number; error?: string };
export type Turn = { role: "user" | "assistant"; content: string };

type ChatMessage =
  | { role: "system" | "user"; content: string }
  | { role: "assistant"; content: string | null; tool_calls?: { id: string; type: "function"; function: { name: string; arguments: string } }[] }
  | { role: "tool"; tool_call_id: string; content: string };

async function chat(messages: ChatMessage[]) {
  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${process.env.OPENAI_API_KEY}` },
    body: JSON.stringify({
      model: process.env.OPENAI_MODEL ?? "gpt-5.4-mini",
      messages,
      tools: Object.entries(TOOLS).map(([name, t]) => ({
        type: "function",
        function: { name, description: t.description, parameters: t.parameters },
      })),
      max_completion_tokens: 4000,
    }),
    signal: AbortSignal.timeout(60_000),
  });
  if (!res.ok) throw new Error(`OpenAI: HTTP ${res.status} ${(await res.text()).slice(0, 300)}`);
  const body = (await res.json()) as { choices: { message: Extract<ChatMessage, { role: "assistant" }> }[] };
  const msg = body.choices[0]?.message;
  if (!msg) throw new Error("OpenAI: empty reply");
  return msg;
}

const rowsOf = (x: unknown) => (Array.isArray(x) ? x.length : x && typeof x === "object" ? 1 : 0);

export async function ask(question: string, history: Turn[] = [], maxSteps = 6): Promise<{ answer: string; steps: Step[] }> {
  if (!process.env.OPENAI_API_KEY) throw new Error("OPENAI_API_KEY is not set");
  const messages: ChatMessage[] = [{ role: "system", content: SYSTEM }, ...history.slice(-6), { role: "user", content: question }];
  const steps: Step[] = [];
  for (let i = 0; i < maxSteps; i++) {
    const msg = await chat(messages);
    messages.push(msg);
    if (!msg.tool_calls?.length) return { answer: msg.content ?? "", steps };
    for (const call of msg.tool_calls) {
      const tool = TOOLS[call.function.name];
      let args: Record<string, string> = {};
      let content: string;
      try {
        args = JSON.parse(call.function.arguments || "{}") as Record<string, string>;
        if (!tool) throw new Error(`unknown tool ${call.function.name}`);
        const started = Date.now();
        const result = await tool.run(args);
        console.log(`agent ${call.function.name} ${JSON.stringify(args).slice(0, 200)} ${Date.now() - started} ms`);
        steps.push({ tool: call.function.name, args, rows: rowsOf(result) });
        content = JSON.stringify(result).slice(0, 30_000);
      } catch (e) {
        const error = (e as Error).message;
        steps.push({ tool: call.function.name, args, rows: 0, error });
        content = JSON.stringify({ error });
      }
      messages.push({ role: "tool", tool_call_id: call.id, content });
    }
  }
  return { answer: "I ran out of steps before finishing. Try a narrower question.", steps };
}
