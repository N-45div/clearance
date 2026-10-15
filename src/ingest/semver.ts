// Just enough semver for Go module and toolchain versions ("v0.60.0", "1.26.9", "1.27.0-0").

type Parsed = { nums: number[]; pre: string };

function parse(v: string): Parsed {
  const s = v.replace(/^v/, "").split("+")[0] ?? "";
  const dash = s.indexOf("-");
  const core = dash < 0 ? s : s.slice(0, dash);
  const pre = dash < 0 ? "" : s.slice(dash + 1);
  const nums = core.split(".").map((n) => Number.parseInt(n, 10) || 0);
  while (nums.length < 3) nums.push(0);
  return { nums, pre };
}

export function compare(a: string, b: string): number {
  const x = parse(a);
  const y = parse(b);
  for (let i = 0; i < 3; i++) {
    const d = (x.nums[i] ?? 0) - (y.nums[i] ?? 0);
    if (d) return Math.sign(d);
  }
  // A pre-release sorts before its release.
  if (x.pre === y.pre) return 0;
  if (!x.pre) return 1;
  if (!y.pre) return -1;
  return x.pre < y.pre ? -1 : 1;
}

export type RangeEvent = { introduced?: string; fixed?: string; last_affected?: string };

// The version to bump to: the lowest "fixed" event above the version in use.
export function fixedAfter(version: string, events: RangeEvent[]): string | undefined {
  return events
    .map((e) => e.fixed)
    .filter((f): f is string => !!f && compare(f, version) > 0)
    .sort(compare)[0];
}
