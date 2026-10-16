// Measures what Clearance's OpenVEX does to a scanner people already run: Trivy on each fleet repo's
// go.mod at its pinned commit, with and without the repo's VEX from the API.
// Needs trivy on PATH. Usage: node scripts/trivy-with-vex.mjs [api base, default the live demo]
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const base = process.argv[2] ?? "https://clearance-lemon.vercel.app/api";
const lock = JSON.parse(readFileSync(join(import.meta.dirname, "../fleet.lock.json"), "utf8"));
const work = mkdtempSync(join(tmpdir(), "clearance-trivy-"));

// --detection-priority comprehensive: without it trivy reports module advisories only, not the standard library.
function trivy(dir, vex) {
  const args = ["fs", "--scanners", "vuln", "--format", "json", "--quiet", "--detection-priority", "comprehensive"];
  if (vex) args.push("--vex", vex, "--show-suppressed");
  const r = JSON.parse(execFileSync("trivy", [...args, dir], { maxBuffer: 64 << 20, encoding: "utf8" }));
  let reported = 0;
  let suppressed = 0;
  for (const x of r.Results ?? []) {
    reported += (x.Vulnerabilities ?? []).length;
    suppressed += (x.ExperimentalModifiedFindings ?? []).length;
  }
  return { reported, suppressed };
}

const rows = [];
for (const { repo, sha } of lock.repos) {
  const dir = join(work, repo);
  mkdirSync(dir);
  for (const f of ["go.mod", "go.sum"]) {
    const res = await fetch(`https://raw.githubusercontent.com/${lock.org}/${repo}/${sha}/${f}`);
    if (res.ok) writeFileSync(join(dir, f), Buffer.from(await res.arrayBuffer()));
  }
  const vex = join(dir, "openvex.json");
  writeFileSync(vex, await (await fetch(`${base}/vex/${repo}`)).text());
  const verdicts = await (await fetch(`${base}/repos/${repo}`)).json();
  const before = trivy(dir);
  const after = trivy(dir, vex);
  rows.push({
    repo,
    trivy: before.reported,
    withVex: after.reported,
    suppressed: after.suppressed,
    notAffected: verdicts.filter((v) => v.status === "not_affected").length,
  });
}
console.table(rows);
const sum = (k) => rows.reduce((a, r) => a + r[k], 0);
console.log(`trivy: ${sum("trivy")} findings; with Clearance's VEX: ${sum("withVex")} (${sum("suppressed")} suppressed; Clearance proved ${sum("notAffected")} not affected)`);
