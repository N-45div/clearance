// `npm run check`: Clearance verdicts for one repo you have checked out, from the govulncheck JSON your CI
// already makes. It builds the same graph the fleet uses, in a graph of its own, decides every advisory
// the repo's versions are in range of, prints the evidence, writes OpenVEX, and exits:
//   0  nothing reachable from shipped code (or --fail-on never)
//   1  a vulnerable function is reachable (from shipped code; from anywhere with --fail-on any)
//   2  the scan failed or the input is unusable, so nothing is claimed
//
//   npm run check -- --run --dir . --vex openvex.json          (runs govulncheck itself)
//   govulncheck -format json ./... > scan.json; echo $? > scan.exit
//   npm run check -- --scan scan.json --scan-exit "$(cat scan.exit)" --dir .
//
// govulncheck's exit code is required: with -format json it exits 0 whether or not it finds anything,
// and a failed run can still write a valid-looking file (a lone config line reads like "nothing found").
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { closeGraph, dropGraph, read } from "./db.ts";
import { loadAdvisories, loadMatches, loadOwners, loadRepos, loadScan } from "./graph/load.ts";
import { ensureSchema } from "./graph/schema.ts";
import { decideAll, type Decision } from "./graph/verdicts.ts";
import { parseCodeowners } from "./ingest/codeowners.ts";
import { parseGoMod, stdlibVersion } from "./ingest/gomod.ts";
import { goAdvisory, queryBatch, type GoAdvisory } from "./ingest/osv.ts";
import type { FleetLock } from "./ingest/pin.ts";
import { readScan } from "./ingest/scans.ts";
import { vexDocument } from "./report.ts";

const OWNER_FILES = [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"];

export type CheckResult = {
  repo: string;
  module: string;
  sha: string;
  scanOk: boolean;
  decisions: Decision[];
  lines: Map<string, number>; // "repo|func" -> line of the call site
  advisories: Map<string, GoAdvisory>;
  // OSV ids for this repo's versions with no Go vulndb record: no symbols, so no verdict either way.
  unjudged: string[];
};

const readOptional = async (path: string) => {
  try {
    return await readFile(path, "utf8");
  } catch {
    return undefined;
  }
};

function gitHead(dir: string): string | undefined {
  try {
    return execFileSync("git", ["-C", dir, "rev-parse", "HEAD"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return undefined;
  }
}

// Runs govulncheck in the checkout and keeps its JSON and its exit code.
export async function runGovulncheck(dir: string): Promise<{ scan: string; exit: number }> {
  const out = join(await mkdtemp(join(tmpdir(), "clearance-")), "scan.json");
  const r = spawnSync("govulncheck", ["-format", "json", "./..."], { cwd: dir, encoding: "utf8", maxBuffer: 1 << 30 });
  if (r.error) throw new Error(`could not run govulncheck (${r.error.message}); install it with go install golang.org/x/vuln/cmd/govulncheck@latest`);
  await writeFile(out, r.stdout);
  if (r.status !== 0) process.stderr.write(r.stderr);
  return { scan: out, exit: r.status ?? -1 };
}

export async function check(opts: { scan: string; scanExit: number; dir: string; name?: string; sha?: string; keep?: boolean }): Promise<CheckResult> {
  const dir = resolve(opts.dir);
  const goModText = await readOptional(join(dir, "go.mod"));
  if (!goModText) throw new Error(`no go.mod in ${dir}`);
  const mod = parseGoMod(goModText);
  const name = opts.name ?? basename(mod.module);
  const sha = opts.sha ?? gitHead(dir) ?? "unknown";
  // Its own graph, so a check never touches the fleet graph on the same server. db.ts reads this when it
  // first connects, which is below.
  process.env.FALKORDB_GRAPH = `clearance_check_${name.replace(/[^\w-]/g, "_")}`;

  let owners: string | undefined;
  for (const f of OWNER_FILES) owners ??= await readOptional(join(dir, f));
  const scan = await readScan(resolve(opts.scan));
  const scanOk = opts.scanExit === 0 && !!scan.config;
  const scanNote = scanOk
    ? null
    : opts.scanExit !== 0
      ? `govulncheck exited ${opts.scanExit}`
      : "the govulncheck JSON has no config message, so the scan did not run";

  await dropGraph();
  try {
    await ensureSchema();
    const org = /^github\.com\/([^/]+)\//.exec(mod.module)?.[1] ?? "local";
    const lock: FleetLock = { org, pinnedAt: new Date().toISOString(), repos: [{ repo: name, branch: "", sha, committedAt: "", owners: null }] };
    const repo = { name, mod, stdlib: stdlibVersion(mod), rules: owners ? parseCodeowners(owners) : [] };
    const pairs = await loadRepos(lock, [repo]);
    await loadOwners([repo]);

    const hits = await queryBatch(pairs);
    const ids = new Set([...hits.values()].flat());
    for (const f of scan.findings) ids.add(f.osv);
    const advisories = new Map<string, GoAdvisory>();
    for (const id of [...ids].filter((i) => i.startsWith("GO-"))) advisories.set(id, await goAdvisory(id));
    const aliased = new Set([...advisories.values()].flatMap((a) => a.aliases));
    const unjudged = [...ids].filter((i) => !i.startsWith("GO-") && !aliased.has(i)).sort();

    await loadAdvisories([...advisories.values()]);
    await loadMatches(hits, advisories);
    await loadScan(
      repo,
      { repo: name, ok: scanOk, exit: opts.scanExit, toolchain: scan.config?.go_version ?? "", note: scanNote },
      scan,
    );
    const decisions = await decideAll();
    const lines = new Map<string, number>();
    for (const d of decisions) {
      if (!d.callSite) continue;
      const [row] = await read<{ line: number }>(
        `MATCH (:Frame {key: $key})-[l:DEFINED_IN]->(:File) RETURN l.line AS line LIMIT 1`,
        { key: `${name}|${d.callSite}` },
      );
      if (row) lines.set(`${name}|${d.callSite}`, row.line);
    }
    return { repo: name, module: mod.module, sha, scanOk, decisions, lines, advisories, unjudged };
  } finally {
    if (!opts.keep) await dropGraph();
    await closeGraph();
  }
}

export function exitCode(r: CheckResult, failOn: "shipped" | "any" | "never"): number {
  if (!r.scanOk) return 2;
  if (failOn === "never") return 0;
  const hit = r.decisions.some((d) => d.status === "affected" && (failOn === "any" || d.reach === "shipped"));
  return hit ? 1 : 0;
}

export function report(r: CheckResult): string {
  const out: string[] = [];
  const by = (s: string, reach?: string) => r.decisions.filter((d) => d.status === s && (!reach || d.reach === reach));
  const site = (d: Decision) => {
    const line = d.callSite ? r.lines.get(`${r.repo}|${d.callSite}`) : undefined;
    return d.file ? `${d.file}${line ? `:${line}` : ""}` : (d.callSite ?? "");
  };
  const fix = (d: Decision) =>
    d.bumps.map((b) => b.replace("=>", " -> ").replace(/ -> $/, " (no fix yet)")).join(", ");
  out.push(`${r.repo} (${r.module}) at ${r.sha.slice(0, 12)}: ${r.decisions.length} advisories in range of the versions it builds with`);
  if (!r.scanOk) out.push(`  the scan is unusable, so every verdict is under investigation and none is "not affected"`);
  for (const [label, list] of [
    ["AFFECTED, reachable from shipped code", by("affected", "shipped")],
    ["affected, only from examples, tests or tooling", by("affected", "examples_tests_only")],
  ] as const) {
    if (!list.length) continue;
    out.push("", `${label}: ${list.length}`);
    for (const d of list) {
      out.push(`  ${d.advisory}  ${d.path[0]} -> ${d.path.at(-1)}`);
      out.push(`      at ${site(d)}${d.owners.length ? `  owned by ${d.owners.join(", ")}` : ""}  fix: ${fix(d)}`);
    }
  }
  const na = by("not_affected");
  if (na.length) {
    out.push("", `not affected (proof: no call path): ${na.length}`);
    for (const d of na) out.push(`  ${d.advisory}  ${d.justification}: ${d.reason}`);
  }
  const ui = by("under_investigation");
  if (ui.length) {
    out.push("", `under investigation (nothing claimed): ${ui.length}`);
    for (const d of ui) out.push(`  ${d.advisory}  ${d.reason}`);
  }
  if (r.unjudged.length) {
    out.push("", `no Go vulndb record, so no function data to judge: ${r.unjudged.join(", ")}`);
  }
  return out.join("\n");
}

if (import.meta.main) {
  const { values } = parseArgs({
    options: {
      scan: { type: "string" },
      "scan-exit": { type: "string" },
      run: { type: "boolean", default: false },
      dir: { type: "string", default: "." },
      name: { type: "string" },
      sha: { type: "string" },
      vex: { type: "string" },
      "fail-on": { type: "string", default: "shipped" },
      keep: { type: "boolean", default: false },
    },
  });
  const failOn = values["fail-on"];
  const exitArg = values["scan-exit"];
  const usable = values.run !== !!values.scan && (!values.scan || /^\d+$/.test(exitArg ?? ""));
  if (!usable || !["shipped", "any", "never"].includes(failOn)) {
    console.error(
      "usage: npm run check -- (--run | --scan scan.json --scan-exit <govulncheck exit code>) [--dir .] [--vex openvex.json]\n" +
        "                        [--fail-on shipped|any|never] [--name repo] [--sha commit] [--keep]\n" +
        "--scan-exit is required with --scan: a failed govulncheck run can still write a valid-looking JSON file.",
    );
    process.exit(64);
  }
  let r: CheckResult;
  try {
    const scan = values.run ? await runGovulncheck(resolve(values.dir)) : { scan: values.scan!, exit: Number(exitArg) };
    r = await check({ scan: scan.scan, scanExit: scan.exit, dir: values.dir, name: values.name, sha: values.sha, keep: values.keep });
  } catch (e) {
    // An error is never a pass, and never reads as "affected" (1) either.
    console.error(`clearance check: ${(e as Error).message}`);
    if (process.env.GITHUB_ACTIONS) console.log(`::error title=clearance check::${(e as Error).message}`);
    process.exit(2);
  }
  console.log(report(r));
  if (values.vex) {
    const rows = r.decisions.map((d) => ({ ...d, aliases: r.advisories.get(d.advisory)?.aliases ?? [] }));
    const org = /^github\.com\/([^/]+)\//.exec(r.module)?.[1] ?? "local";
    const doc = vexDocument({ org, repo: r.repo, sha: r.sha, module: r.module }, rows, new Date().toISOString(), "Clearance check with govulncheck call paths in FalkorDB");
    await writeFile(values.vex, JSON.stringify(doc, null, 2));
    console.log(`\nOpenVEX: ${values.vex} (${doc.statements.length} statements)`);
  }
  process.exitCode = exitCode(r, failOn as "shipped" | "any" | "never");
  // In GitHub Actions, the outcome also shows as an annotation on the run.
  if (process.env.GITHUB_ACTIONS) {
    const n = (s: string, reach?: string) => r.decisions.filter((d) => d.status === s && (!reach || d.reach === reach)).length;
    const line = `${r.repo}: ${n("affected", "shipped")} reachable from shipped code, ${n("affected", "examples_tests_only")} only from examples or tests, ${n("not_affected")} not affected, ${n("under_investigation")} under investigation`;
    console.log(`::${process.exitCode ? "error" : "notice"} title=clearance check (exit ${process.exitCode})::${line}`);
  }
}
