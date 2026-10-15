// Turns govulncheck JSON into graph facts: which vulnerable packages a repo imports, and the call
// chains from the repo's own code into vulnerable functions. Verdicts are not decided here; they are
// read off the graph afterwards (src/graph/verdicts.ts).
import { readFile } from "node:fs/promises";

export type Frame = {
  module: string;
  version?: string;
  package?: string;
  function?: string;
  receiver?: string;
  position?: { filename?: string; line: number };
};

export type Finding = { osv: string; fixed_version?: string; trace: Frame[] };

export type ScanConfig = {
  scanner_version: string;
  go_version: string;
  db_last_modified: string;
  scan_level: string;
};

export type Scan = { config: ScanConfig | undefined; findings: Finding[] };

export type Level = "module" | "package" | "symbol";

export async function readScan(file: string): Promise<Scan> {
  const scan: Scan = { config: undefined, findings: [] };
  for (const line of (await readFile(file, "utf8")).split("\n")) {
    if (!line.trim()) continue;
    const msg = JSON.parse(line) as { config?: ScanConfig; finding?: Finding };
    if (msg.config) scan.config = msg.config;
    if (msg.finding) scan.findings.push(msg.finding);
  }
  return scan;
}

export function levelOf(f: Finding): Level {
  const top = f.trace[0];
  if (top?.function) return "symbol";
  if (top?.package) return "package";
  return "module";
}

// Same naming as the Go vulndb symbols: "Client.Do" for methods, "Get" for functions.
export function funcKey(fr: Frame): string {
  const recv = fr.receiver?.replace(/^\*/, "");
  return `${fr.package}.${recv ? `${recv}.` : ""}${fr.function}`;
}

export type CallFacts = {
  imports: Set<string>;
  // caller -> callee, both func keys, one entry per distinct pair
  calls: Map<string, { from: Frame; to: Frame }>;
  entries: Map<string, Frame>;
  levels: Map<string, Level>;
};

// govulncheck reports a finding at every level it reaches, so the strongest level wins per advisory.
export function callFacts(scan: Scan): CallFacts {
  const rank: Record<Level, number> = { module: 0, package: 1, symbol: 2 };
  const facts: CallFacts = { imports: new Set(), calls: new Map(), entries: new Map(), levels: new Map() };
  for (const f of scan.findings) {
    const level = levelOf(f);
    const prev = facts.levels.get(f.osv);
    if (!prev || rank[level] > rank[prev]) facts.levels.set(f.osv, level);
    const top = f.trace[0];
    if (top?.package) facts.imports.add(top.package);
    if (level !== "symbol") continue;
    // trace[0] is the vulnerable function; each next frame calls the one before; the last frame is
    // the entry point in the repo's own code.
    for (let i = 0; i + 1 < f.trace.length; i++) {
      const callee = f.trace[i]!;
      const caller = f.trace[i + 1]!;
      facts.calls.set(`${funcKey(caller)}>${funcKey(callee)}`, { from: caller, to: callee });
    }
    const entry = f.trace.at(-1)!;
    facts.entries.set(funcKey(entry), entry);
  }
  return facts;
}

// govulncheck writes positions relative to the frame's module root. Only frames in the repo's own
// module are files in the repo (and so have CODEOWNERS); the repo's go.mod sits at its root.
export function repoPath(fr: Frame, repoModule: string): string | undefined {
  if (fr.module !== repoModule || !fr.position?.filename) return undefined;
  return fr.position.filename.replace(/^\.?\//, "");
}
