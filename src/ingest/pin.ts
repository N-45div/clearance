// Pins every fleet repo to the current head of its default branch and writes fleet.lock.json.
// Everything after this (go.mod, CODEOWNERS, govulncheck) reads the repo at that exact commit.
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { api, rawFile } from "./github.ts";

export type Fleet = { org: string; repos: string[] };
export type Pin = { repo: string; branch: string; sha: string; committedAt: string; owners: string | null };
export type FleetLock = { org: string; pinnedAt: string; repos: Pin[] };

const ROOT = join(import.meta.dirname, "../..");
const OWNER_FILES = [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"];

async function pin(org: string, repo: string): Promise<Pin> {
  const meta = await api<{ default_branch: string }>(`/repos/${org}/${repo}`);
  const head = await api<{ sha: string; commit: { committer: { date: string } } }>(
    `/repos/${org}/${repo}/commits/${meta.default_branch}`,
  );
  let owners: string | null = null;
  for (const path of OWNER_FILES) {
    if (await rawFile(org, repo, head.sha, path)) {
      owners = path;
      break;
    }
  }
  return { repo, branch: meta.default_branch, sha: head.sha, committedAt: head.commit.committer.date, owners };
}

if (import.meta.main) {
  const fleet = JSON.parse(await readFile(join(ROOT, "fleet.json"), "utf8")) as Fleet;
  const repos: Pin[] = [];
  for (const repo of fleet.repos) {
    const p = await pin(fleet.org, repo);
    console.log(`${repo.padEnd(30)} ${p.branch.padEnd(7)} ${p.sha.slice(0, 12)} owners=${p.owners ?? "-"}`);
    repos.push(p);
  }
  const lock: FleetLock = { org: fleet.org, pinnedAt: new Date().toISOString(), repos };
  await writeFile(join(ROOT, "fleet.lock.json"), JSON.stringify(lock, null, 2) + "\n");
}
