// Builds the fleet graph: repos at their pinned commits, the module versions they build with, the
// advisories OSV matches against those versions, the vulnerable functions, and CODEOWNERS teams.
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { closeGraph } from "../db.ts";
import { loadAdvisories, loadMatches, loadOwners, loadRepos, readRepos } from "../graph/load.ts";
import { ensureSchema } from "../graph/schema.ts";
import { goAdvisory, queryBatch, type GoAdvisory } from "./osv.ts";
import type { FleetLock } from "./pin.ts";

const ROOT = join(import.meta.dirname, "../..");

if (import.meta.main) {
  const lock = JSON.parse(await readFile(join(ROOT, "fleet.lock.json"), "utf8")) as FleetLock;
  await ensureSchema();
  const repos = await readRepos(lock);
  const pairs = await loadRepos(lock, repos);
  console.log(`repos ${repos.length}, module versions ${pairs.length}`);
  console.log(`owner rules with teams ${await loadOwners(repos)}`);

  const hits = await queryBatch(pairs);
  const ids = new Set([...hits.values()].flat());
  const goIds = [...ids].filter((id) => id.startsWith("GO-"));
  const advisories = new Map<string, GoAdvisory>();
  for (const id of goIds) advisories.set(id, await goAdvisory(id));
  const aliased = new Set([...advisories.values()].flatMap((a) => a.aliases));
  const unreviewed = [...ids].filter((id) => !id.startsWith("GO-") && !aliased.has(id));
  console.log(`advisories ${goIds.length} (Go vulndb), ${unreviewed.length} other ids with no Go vulndb record`);

  console.log(`vulnerable functions ${await loadAdvisories([...advisories.values()])}`);
  console.log(`version matches ${await loadMatches(hits, advisories)}`);
  await closeGraph();
}
