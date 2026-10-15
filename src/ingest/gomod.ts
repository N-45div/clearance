// Parses the parts of a go.mod that decide which module versions a build really uses.

export type Requirement = { path: string; version: string; direct: boolean };
export type GoMod = {
  module: string;
  go: string | undefined;
  toolchain: string | undefined;
  requires: Requirement[];
  // Requirements replaced by a local directory: they are not fetched from a module proxy.
  local: string[];
};

type Replace = { from: string; fromVersion?: string; to: string; toVersion?: string };

function stripComment(line: string): { text: string; indirect: boolean } {
  const i = line.indexOf("//");
  if (i < 0) return { text: line.trim(), indirect: false };
  return { text: line.slice(0, i).trim(), indirect: /\/\/\s*indirect\b/.test(line.slice(i)) };
}

function unquote(s: string): string {
  return s.startsWith('"') || s.startsWith("`") ? s.slice(1, -1) : s;
}

function parseReplace(spec: string): Replace | undefined {
  const [left, right] = spec.split("=>").map((s) => s.trim().split(/\s+/).map(unquote));
  if (!left?.[0] || !right?.[0]) return undefined;
  return { from: left[0], fromVersion: left[1], to: right[0], toVersion: right[1] };
}

export function parseGoMod(text: string): GoMod {
  const mod: GoMod = { module: "", go: undefined, toolchain: undefined, requires: [], local: [] };
  const replaces: Replace[] = [];
  let block: string | undefined;

  for (const raw of text.split(/\r?\n/)) {
    const { text: line, indirect } = stripComment(raw);
    if (!line) continue;
    if (block) {
      if (line === ")") {
        block = undefined;
        continue;
      }
      take(block, line, indirect);
      continue;
    }
    const m = /^(\w+)\s*(\()?\s*(.*)$/.exec(line);
    if (!m) continue;
    const [, verb, open, rest] = m;
    if (open) block = verb;
    else if (verb) take(verb, rest ?? "", indirect);
  }

  function take(verb: string, rest: string, indirect: boolean) {
    const parts = rest.split(/\s+/).map(unquote);
    if (verb === "module") mod.module = parts[0] ?? "";
    else if (verb === "go") mod.go = parts[0];
    else if (verb === "toolchain") mod.toolchain = parts[0];
    else if (verb === "require" && parts[0] && parts[1]) {
      mod.requires.push({ path: parts[0], version: parts[1], direct: !indirect });
    } else if (verb === "replace") {
      const r = parseReplace(rest);
      if (r) replaces.push(r);
    }
  }

  // A replace swaps the module the build actually uses, so vulnerability matching must follow it.
  for (const req of mod.requires) {
    const r = replaces.find((x) => x.from === req.path && (!x.fromVersion || x.fromVersion === req.version));
    if (!r) continue;
    if (r.to.startsWith(".") || r.to.startsWith("/")) {
      mod.local.push(req.path);
    } else if (r.toVersion) {
      req.path = r.to;
      req.version = r.toVersion;
    }
  }
  mod.requires = mod.requires.filter((r) => !mod.local.includes(r.path));
  return mod;
}

// The standard library version the repo builds with: the toolchain line wins over the go line.
export function stdlibVersion(mod: GoMod): string | undefined {
  const v = mod.toolchain?.replace(/^go/, "") ?? mod.go;
  if (!v) return undefined;
  return /^\d+\.\d+$/.test(v) ? `${v}.0` : v;
}
