import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

const UA = { "User-Agent": "clearance (graph hacks)" };
const CACHE = join(import.meta.dirname, "../../.cache");

// Files are fetched at a pinned commit, so a cached copy never goes stale.
export async function rawFile(org: string, repo: string, sha: string, path: string): Promise<string | undefined> {
  const cached = join(CACHE, "raw", org, repo, sha, path);
  try {
    return await readFile(cached, "utf8");
  } catch {}
  const res = await fetch(`https://raw.githubusercontent.com/${org}/${repo}/${sha}/${path}`, { headers: UA });
  if (res.status === 404) return undefined;
  if (!res.ok) throw new Error(`raw ${org}/${repo}@${sha}/${path}: HTTP ${res.status}`);
  const text = await res.text();
  await mkdir(dirname(cached), { recursive: true });
  await writeFile(cached, text);
  return text;
}

export async function api<T>(path: string): Promise<T> {
  const headers: Record<string, string> = { ...UA, Accept: "application/vnd.github+json" };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  const res = await fetch(`https://api.github.com${path}`, { headers });
  if (!res.ok) throw new Error(`GitHub ${path}: HTTP ${res.status} ${await res.text()}`);
  return (await res.json()) as T;
}
