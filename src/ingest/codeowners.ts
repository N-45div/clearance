// CODEOWNERS with GitHub's rule that the last matching line wins.
// Only team handles (@org/team) are kept: individual people are personal data and stay out of the graph.

export type OwnerRule = { pattern: string; teams: string[]; order: number };

export function parseCodeowners(text: string): OwnerRule[] {
  const rules: OwnerRule[] = [];
  text.split(/\r?\n/).forEach((raw, order) => {
    const line = raw.replace(/\s#.*$/, "").trim();
    if (!line || line.startsWith("#")) return;
    const [pattern, ...owners] = line.split(/\s+/);
    if (!pattern) return;
    rules.push({ pattern, teams: owners.filter((o) => /^@[\w.-]+\/[\w.-]+$/.test(o)), order });
  });
  return rules;
}

function toRegExp(pattern: string): RegExp {
  let p = pattern;
  const anchored = p.startsWith("/") || p.slice(0, -1).includes("/");
  p = p.replace(/^\//, "");
  const dirOnly = p.endsWith("/");
  p = p.replace(/\/$/, "");
  let re = "";
  for (let i = 0; i < p.length; i++) {
    const c = p[i]!;
    if (c === "*" && p[i + 1] === "*") {
      re += ".*";
      i++;
      if (p[i + 1] === "/") i++;
    } else if (c === "*") re += "[^/]*";
    else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  const prefix = anchored ? "^" : "^(?:.*/)?";
  // A pattern names a file or a directory; a directory owns everything under it.
  return new RegExp(prefix + re + (dirOnly ? "/.*$" : "(?:/.*)?$"));
}

export function ownersFor(rules: OwnerRule[], path: string): OwnerRule | undefined {
  let hit: OwnerRule | undefined;
  for (const rule of rules) {
    if (rule.pattern === "*" || toRegExp(rule.pattern).test(path)) hit = rule;
  }
  return hit;
}
