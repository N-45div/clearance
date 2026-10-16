export type Status = "affected" | "not_affected" | "under_investigation";

export type Summary = {
  flagged: number; affected: number; notAffected: number; underInvestigation: number;
  repos: number; scanned: number; advisories: number; pullRequests: number; teams: number;
};

export type AdvisoryRow = {
  id: string; summary: string; published: string; aliases: string[];
  repos: number; affected: number; notAffected: number; underInvestigation: number;
};

export type RepoVerdict = {
  repo: string; sha: string; status: Status; justification: string | null; reason: string;
  path: string[]; callSite: string | null; file: string | null; owners: string[]; bumps: string[];
  reach: "shipped" | "examples_tests_only" | null; entryFile: string | null; decidedAt: string;
};

export type BlastRadius = {
  advisory: { id: string; summary: string; published: string; modified: string; aliases: string[]; url: string };
  counts: { flagged: number; affected: number; notAffected: number; underInvestigation: number; examplesTestsOnly: number };
  repos: RepoVerdict[];
};

export type Frame = { i: number; key: string; name: string; package: string; module: string; file: string | null; line: number | null; owners: string[] };

export type Evidence = {
  v: RepoVerdict & { key: string };
  sha: string; org: string; module: string;
  frames: Frame[];
  history: { status: string; justification: string | null; decidedAt: string; supersededAt: string | null; repoSha: string; current: boolean }[];
};

export type PlannedFix = { repo: string; module: string; from: string; to: string | null; advisories: string[]; teams: string[] };
export type Teams = { owned: { team: string; verdicts: number; repos: string[] }[]; unowned: { verdicts: number; repos: string[] } };
export type GraphData = { nodes: { id: number; labels: string[]; color: string; visible: boolean; data: Record<string, string> }[]; links: unknown[] };
export type Step = { tool: string; args: Record<string, string>; rows: number; error?: string };
export type Answer = { answer: string; steps: Step[] };

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`/api${path}`);
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(body.error ?? `${path}: HTTP ${res.status}`);
  }
  return (await res.json()) as T;
}

export const api = {
  summary: () => get<Summary>("/summary"),
  advisories: () => get<AdvisoryRow[]>("/advisories"),
  blastRadius: (id: string) => get<BlastRadius>(`/advisories/${id}`),
  graph: (id: string) => get<GraphData>(`/graph/${id}`),
  evidence: (repo: string, id: string) => get<Evidence>(`/evidence/${repo}/${id}`),
  issue: (repo: string, id: string) => get<{ title: string; body: string }>(`/issue/${repo}/${id}`),
  plan: () => get<PlannedFix[]>("/plan"),
  teams: () => get<Teams>("/teams"),
  ask: async (question: string, history: { role: "user" | "assistant"; content: string }[]) => {
    const res = await fetch("/api/ask", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question, history }),
    });
    const body = (await res.json()) as Answer & { error?: string };
    if (!res.ok || body.error) throw new Error(body.error ?? `HTTP ${res.status}`);
    return body;
  },
};

export const parseBump = (b: string) => {
  const [left = "", to = ""] = b.split("=>");
  const at = left.lastIndexOf("@");
  return { module: left.slice(0, at), from: left.slice(at + 1), to: to || null };
};
