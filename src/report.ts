// What a security team hands on: an OpenVEX document per repo, and an issue draft per affected verdict.
// Both are built from verdicts the graph already decided; nothing here decides anything.
import { createHash } from "node:crypto";
import { parseBump } from "./graph/fleet.ts";

export type VerdictRow = {
  advisory: string;
  aliases?: string[];
  status: "affected" | "not_affected" | "under_investigation" | "fixed";
  justification: string | null;
  reason: string;
  bumps: string[];
};

export type RepoRef = { org: string; repo: string; sha: string };

const bumpText = (bumps: string[]) =>
  bumps
    .map(parseBump)
    .map((b) => (b.to ? `bump ${b.module} from ${b.from} to ${b.to}` : `${b.module} ${b.from} has no fixed version yet`))
    .join("; ");

// OpenVEX v0.2.0: https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md
export function vexDocument(ref: RepoRef, verdicts: VerdictRow[], timestamp: string, tooling: string) {
  const product = { "@id": `pkg:github/${ref.org}/${ref.repo}@${ref.sha}` };
  const statements = verdicts.map((v) => {
    const s: Record<string, unknown> = {
      vulnerability: { name: v.advisory, ...(v.aliases?.length ? { aliases: v.aliases } : {}) },
      products: [product],
      status: v.status,
    };
    if (v.status === "not_affected") {
      s.justification = v.justification;
      s.impact_statement = v.reason;
    }
    if (v.status === "affected") s.action_statement = `${bumpText(v.bumps)}. ${v.reason}.`;
    if (v.status === "under_investigation") s.status_notes = v.reason;
    return s;
  });
  const id = createHash("sha256").update(JSON.stringify([product, statements])).digest("hex").slice(0, 32);
  return {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": `urn:clearance:vex:${id}`,
    author: "Clearance",
    timestamp,
    version: 1,
    tooling,
    statements,
  };
}

export type Frame = { name: string; package: string; module: string; file: string | null; line: number | null; owners: string[] };

export type IssueInput = {
  ref: RepoRef;
  advisory: { id: string; summary: string; url: string; aliases?: string[] };
  bumps: string[];
  frames: Frame[];
  owners: string[];
  decidedAt: string;
  scanner: string;
};

export function issueDraft(x: IssueInput): { title: string; body: string } {
  const repoFrames = x.frames.filter((f) => f.file);
  const site = repoFrames.at(-1);
  const vuln = x.frames.at(-1);
  const link = (f: Frame) =>
    f.file ? `[\`${f.file}:${f.line}\`](https://github.com/${x.ref.org}/${x.ref.repo}/blob/${x.ref.sha}/${f.file}#L${f.line})` : `\`${f.package}\``;
  const title = `${x.advisory.id}: ${x.advisory.summary}${site ? ` (reached from ${site.name})` : ""}`;
  const body = [
    `**Clearance verdict: affected** at ${x.ref.sha.slice(0, 12)}, decided ${x.decidedAt}.`,
    "",
    `[${x.advisory.id}](${x.advisory.url}): ${x.advisory.summary}${x.advisory.aliases?.length ? ` (${x.advisory.aliases.join(", ")})` : ""}`,
    "",
    `### Call path into the vulnerable code`,
    ...x.frames.map((f, i) => `${i + 1}. \`${f.name}\` ${link(f)}`),
    "",
    site ? `The repo's own code touches the dependency at ${link(site)}${x.owners.length ? `, owned by ${x.owners.join(", ")}` : ""}.` : "",
    vuln ? `The vulnerable function is \`${vuln.package}.${vuln.name}\`.` : "",
    "",
    `### Fix`,
    `${bumpText(x.bumps)}.`,
    "",
    `Evidence: ${x.scanner}, stored as a call path in FalkorDB. Drafted by Clearance; not posted anywhere.`,
  ];
  return { title, body: body.filter((l, i, a) => !(l === "" && a[i - 1] === "")).join("\n") };
}
