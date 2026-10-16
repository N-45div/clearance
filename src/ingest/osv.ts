// Which advisories hit which module versions, from OSV, and the vulnerable symbols from the Go vulndb.
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { CACHE_DIR } from "../cache.ts";
import type { RangeEvent } from "./semver.ts";

const CACHE = join(CACHE_DIR, "vulndb");

export type Pair = { path: string; version: string };

export type GoAdvisory = {
  id: string;
  summary: string;
  published: string;
  modified: string;
  aliases: string[];
  affected: {
    module: string;
    events: RangeEvent[];
    imports: { path: string; symbols: string[] }[];
  }[];
};

// OSV matches versions against advisory ranges server side; we never re-implement that.
export async function queryBatch(pairs: Pair[]): Promise<Map<string, string[]>> {
  const hits = new Map<string, string[]>();
  for (let i = 0; i < pairs.length; i += 500) {
    const chunk = pairs.slice(i, i + 500);
    const res = await fetch("https://api.osv.dev/v1/querybatch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        queries: chunk.map((p) => ({ package: { name: p.path, ecosystem: "Go" }, version: p.version })),
      }),
    });
    if (!res.ok) throw new Error(`OSV querybatch: HTTP ${res.status}`);
    const body = (await res.json()) as { results: { vulns?: { id: string }[] }[] };
    body.results.forEach((r, j) => {
      const ids = (r.vulns ?? []).map((v) => v.id);
      const p = chunk[j];
      if (p && ids.length) hits.set(`${p.path}@${p.version}`, ids);
    });
  }
  return hits;
}

type RawOsv = {
  id: string;
  summary?: string;
  details?: string;
  published: string;
  modified: string;
  aliases?: string[];
  affected?: {
    package: { name: string };
    ranges?: { events: RangeEvent[] }[];
    ecosystem_specific?: { imports?: { path: string; symbols?: string[] }[] };
  }[];
};

export async function goAdvisory(id: string): Promise<GoAdvisory> {
  const cached = join(CACHE, `${id}.json`);
  let raw: RawOsv;
  try {
    raw = JSON.parse(await readFile(cached, "utf8")) as RawOsv;
  } catch {
    const res = await fetch(`https://vuln.go.dev/ID/${id}.json`);
    if (!res.ok) throw new Error(`vuln.go.dev ${id}: HTTP ${res.status}`);
    const text = await res.text();
    await mkdir(CACHE, { recursive: true });
    await writeFile(cached, text);
    raw = JSON.parse(text) as RawOsv;
  }
  return {
    id: raw.id,
    summary: raw.summary ?? raw.details?.split("\n")[0] ?? raw.id,
    published: raw.published,
    modified: raw.modified,
    aliases: raw.aliases ?? [],
    affected: (raw.affected ?? []).map((a) => ({
      module: a.package.name,
      events: (a.ranges ?? []).flatMap((r) => r.events),
      imports: (a.ecosystem_specific?.imports ?? []).map((imp) => ({ path: imp.path, symbols: imp.symbols ?? [] })),
    })),
  };
}
