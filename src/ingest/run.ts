// Builds the fleet graph: repos at their pinned commits, the module versions they build with, the
// advisories OSV matches against those versions, the vulnerable functions, and CODEOWNERS teams.
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { closeGraph } from "../db.ts";
import { loadAdvisories, loadMatches, loadOwners, loadRepos, loadScan, readRepos, type ScanStatus } from "../graph/load.ts";
import { ensureSchema } from "../graph/schema.ts";
import { goAdvisory, queryBatch, type GoAdvisory } from "./osv.ts";
import type { FleetLock } from "./pin.ts";
import { readScan, type Scan } from "./scans.ts";

const ROOT = join(import.meta.dirname, "../..");
const SCANS = join(ROOT, "data/scans");

// data/scans holds one govulncheck JSON per repo plus _status.tsv from scripts/scan.sh.
async function readScans(lock: FleetLock): Promise<Map<string, { status: ScanStatus; scan: Scan | undefined }>> {
  const out = new Map<string, { status: ScanStatus; scan: Scan | undefined }>();
  let tsv = "";
  try {
    tsv = await readFile(join(SCANS, "_status.tsv"), "utf8");
  } catch {
    return out;
  }
  // Why a scan failed, written by hand after looking at the scan's stderr.
  let notes: Record<string, string> = {};
  try {
    notes = JSON.parse(await readFile(join(SCANS, "_notes.json"), "utf8")) as Record<string, string>;
  } catch {}
  for (const line of tsv.split("\n")) {
    const [repo, sha, toolchain, exit] = line.split("\t");
    if (!repo || !lock.repos.some((p) => p.repo === repo && p.sha === sha)) continue;
    const code = Number(exit);
    // govulncheck -format json exits 0 whether or not it finds anything; non-zero is a failed scan.
    const status: ScanStatus = { repo, ok: code === 0, exit: code, toolchain: toolchain ?? "", note: notes[repo] ?? null };
    let scan: Scan | undefined;
    try {
      scan = await readScan(join(SCANS, `${repo}.json`));
    } catch {}
    out.set(repo, { status, scan });
  }
  return out;
}

if (import.meta.main) {
  const lock = JSON.parse(await readFile(join(ROOT, "fleet.lock.json"), "utf8")) as FleetLock;
  await ensureSchema();
  const repos = await readRepos(lock);
  const pairs = await loadRepos(lock, repos);
  console.log(`repos ${repos.length}, module versions ${pairs.length}`);
  console.log(`owner rules with teams ${await loadOwners(repos)}`);

  const hits = await queryBatch(pairs);
  const scans = await readScans(lock);
  const ids = new Set([...hits.values()].flat());
  // govulncheck can find advisories the go.mod versions alone did not (e.g. the build list differs).
  for (const s of scans.values()) for (const f of s.scan?.findings ?? []) ids.add(f.osv);
  const goIds = [...ids].filter((id) => id.startsWith("GO-"));
  const advisories = new Map<string, GoAdvisory>();
  for (const id of goIds) advisories.set(id, await goAdvisory(id));
  const aliased = new Set([...advisories.values()].flatMap((a) => a.aliases));
  const unreviewed = [...ids].filter((id) => !id.startsWith("GO-") && !aliased.has(id));
  console.log(`advisories ${goIds.length} (Go vulndb), ${unreviewed.length} other ids with no Go vulndb record`);

  console.log(`vulnerable functions ${await loadAdvisories([...advisories.values()])}`);
  console.log(`version matches ${await loadMatches(hits, advisories)}`);

  for (const repo of repos) {
    const s = scans.get(repo.name);
    if (!s) {
      console.log(`${repo.name.padEnd(28)} not scanned`);
      continue;
    }
    const n = await loadScan(repo, s.status, s.scan);
    const state = s.status.ok ? "ok" : `FAILED (exit ${s.status.exit})`;
    console.log(`${repo.name.padEnd(28)} scan ${state}: imports ${n.imports}, call edges ${n.calls}, entries ${n.entries}, owned files ${n.files}`);
  }
  await closeGraph();
}
