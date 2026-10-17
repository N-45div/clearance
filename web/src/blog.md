---
title: "278 alerts, 65 provably safe: answering \"are we affected?\" with a graph"
published: false
tags: graphdatabase, go, security, falkordb
description: "Scanners flag every service that uses a vulnerable Go library. Clearance proves which ones actually reach the broken function, with call paths in a FalkorDB graph."
---

A Go vulnerability landed this month: [GO-2026-6609](https://pkg.go.dev/vuln/GO-2026-6609). It's about `net/http` placing no limit on parsed Range headers. Across 20 of Grafana's open-source Go services, each pinned to an exact commit, a version-only scanner would flag 11 of them.

That's the usual result. A scanner sees that your `go.mod` (or your Go toolchain) falls inside the advisory's version range, so it raises an alert. What it doesn't check is whether your code ever *calls* the broken function. So eleven teams each get a ticket, and each of them spends an afternoon finding out whether they actually need to do anything.

For that one advisory, the real answer was three affected, seven not affected and one unknown. One of the three affected is only reachable through k6's `examples/secrets/mock_server.go`, so it's real but low priority. The seven have no call path at all from their code to the vulnerable function. The unknown one is a repo whose reachability scan failed, so nothing is claimed about it. Seven of the eleven alerts were noise. The trouble is that "not affected" is only worth something if you can prove it.

During Graph Hacks (WeMakeDevs x [FalkorDB](https://www.falkordb.com)) I built **Clearance** to produce that proof. For every service and every advisory it gives one of two answers. Either the service is **affected**, and you get the exact call path, the file and line where your code enters it, the team that owns that file, and the version to bump to. Or it's **not affected**, and you get the proof that no path exists, written as an [OpenVEX](https://github.com/openvex/spec) statement you can ship.

It's live at [clearance-lemon.vercel.app](https://clearance-lemon.vercel.app), and the code is at [github.com/N-45div/clearance](https://github.com/N-45div/clearance) (MIT).

## The question is a path

"Is mimir affected by GO-2026-6609?" sounds like a yes/no question. Really it's this question: *is there a chain of calls from mimir's own code to `net/http.fileHandler.ServeHTTP`?* That's a path question, and path questions belong in a graph.

Clearance builds that graph from four public sources. Each repo's `go.mod` at its pinned commit gives the module versions it builds with and the Go toolchain it declares. OSV and the Go vulnerability database give the advisories, their version ranges, and the specific packages and functions that are vulnerable. [govulncheck](https://go.dev/doc/security/vuln/), run on each repo at its pinned commit, gives the call stacks that lead toward vulnerable code, and those become the reachability evidence. CODEOWNERS says which team owns the file where a path starts.

All of it goes into one FalkorDB graph. Here's the core of the model:

```
(Repo)-[:REQUIRES|BUILT_WITH]->(ModuleVersion)-[:VULNERABLE_TO]->(Advisory)
(Advisory)-[:VULNERABLE_FUNC]->(Func)
(Repo)-[:ENTRY]->(Frame)-[:CALLS]->(Frame)-[:IS]->(Func)
(Frame)-[:DEFINED_IN {line}]->(File)-[:OWNED_BY]->(Team)
(Verdict)-[:FOR]->(Repo), (Verdict)-[:ABOUT]->(Advisory), (Verdict)-[:SUPERSEDES]->(Verdict)
```

A verdict comes out of it in three steps. First comes the blast radius: every repo with an edge to a module version the advisory covers. A version-only scanner stops here, and for this fleet that's 278 alerts across 50 advisories. Then comes reachability. For each of those repos, Clearance looks for a path from one of its entry points to a frame that govulncheck flagged as a call into a function the advisory names. If there is one, the repo is affected, and the shortest path that starts in shipped code is the evidence. If there's no path, the repo is not affected, and the justification depends on why. A repo that imports the vulnerable package but never reaches the vulnerable functions gets `vulnerable_code_not_in_execute_path`. A repo that requires the module but never imports the package gets `vulnerable_code_not_present`.

The language model never decides a verdict. Verdicts come from Cypher; the model can only read them.

## The night I took down the database

The first version of the reachability query was the obvious one: list every path, then sort.

```cypher
MATCH p = (e)-[:CALLS*0..30]->(t) ... ORDER BY length(p)
```

It worked fine on my laptop against FalkorDB 6.0.2 in Docker. Then I pointed it at the free FalkorDB Cloud instance, which has 100 MB of memory, and the instance went down.

The cause is `net/http`'s call chains. They branch a lot, so the number of distinct paths grows combinatorially, and asking for all of them so they can be sorted means holding all of them in memory. My next attempt was `algo.SPpaths` per entry/target pair. It crashed too.

Two changes fixed it.

The first was giving every repo its own frames. At first a function was a single shared `Func` node, and every `CALLS` edge carried a `repo` property that each path query had to filter on, so every traversal walked a graph shared by all twenty repos. Now each function appears once per repo as a `Frame` with key `repo|func`, and frames from different repos never connect. A path search for mimir can only ever touch mimir's evidence, and the query needs no edge filter.

The second was asking for less. I only need one path per entry point, the shortest one, because that's what a human reads. `shortestPath` is a breadth-first search, so it stays small however much the chains branch. One FalkorDB detail I learned the hard way: `shortestPath` is only allowed in a `WITH` or `RETURN` clause, not in `MATCH`.

```cypher
MATCH (:Advisory {id: $advisory})-[:VULNERABLE_FUNC]->(:Func)<-[:IS]-(t:Frame {repo: $repo, vulnerable: true})
MATCH (:Repo {name: $repo})-[:ENTRY]->(e:Frame)
WITH e, shortestPath((e)-[:CALLS*1..30]->(t)) AS p
WHERE p IS NOT NULL
OPTIONAL MATCH (e)-[:DEFINED_IN]->(file:File)
RETURN [n IN nodes(p) | n.func] AS path, file.path AS entryFile, length(p) AS hops
ORDER BY hops LIMIT 200
```

The `vulnerable: true` flag on the target frame matters as well. It restricts the targets to the frames govulncheck itself reported as the vulnerable call, rather than every frame that happens to share a function name.

After the rewrite, the verdict counts were identical to those from the old query (278 / 195 / 65 / 18), and the Cloud instance stopped falling over.

## What a verdict looks like

Here's mimir for GO-2026-6609, exactly as the graph returns it. mimir's own `pkg/api.activityTrackingMiddleware.ServeHTTP` calls `net/http.fileHandler.ServeHTTP` directly. That call sits in `pkg/api/activity_tracking.go` on line 72. CODEOWNERS gives that file to `@grafana/mimir-maintainers` (last match wins). The fix is to bump the Go toolchain from 1.26.7 to 1.26.9.

And here's cloudcost-exporter, which imports `net/http` but never reaches the vulnerable code. This is its real OpenVEX statement:

```json
{
  "vulnerability": { "name": "GO-2026-6609", "aliases": ["CVE-2026-78667"] },
  "products": [{ "@id": "pkg:github/grafana/cloudcost-exporter@cf188ae13581e853661fb9277da18319b7b993e7" }],
  "status": "not_affected",
  "justification": "vulnerable_code_not_in_execute_path",
  "impact_statement": "net/http is imported, but no call path from this repo's code reaches the vulnerable functions"
}
```

The product is pinned to an exact commit. That's deliberate, because the statement is only true for that commit.

## "I don't know" is a verdict

The tempting shortcut is to treat "no path found" as "safe". But "no path found" might only mean the analysis never ran.

Two of the twenty scans failed. On Alloy, govulncheck ran out of memory at 31 GB on `./...`, and Alloy's shipped binary is built from a separate `collector/` module anyway. Beyla's packages need `go generate` to produce eBPF code before they even type-check.

Clearance doesn't guess for these. Every verdict for those two repos is `under_investigation`, with the reason stated. The same applies when an advisory is newer than the vulnerability database the scan used. That accounts for 18 of the 278 alerts. They're never shown as safe, and the Ask agent is told never to present them as safe either.

Paths that start only in `examples/`, `tests/` or `tools/` are marked `examples_tests_only`. They're still affected, but at a lower priority. That's the k6 case above.

## Code moves; verdicts remember

A verdict is only true for a specific commit. So every verdict is stored as a `Verdict` node, and when the facts change (a new commit, a modified advisory, a different path), a new `Verdict` is linked to the old one with `SUPERSEDES`.

I tested this for real on day two. I re-pinned mimir and k6 to their current heads. Their old call chains were dropped, and their verdicts immediately became `under_investigation: no reachability scan at this commit yet`. After a rescan on a spot VM, they were decided again. The history for mimir and GO-2026-6609 now reads:

```
affected             @ b082ea4f   09:28
under_investigation  @ c7e3bb6d   09:34
affected             @ c7e3bb6d   09:40   (fresh evidence)
```

None of this needs a separate audit log; it's all in the graph. A **Changes** tab shows the history across the whole fleet.

## Letting agents in, read-only

There's a triage agent in the Ask tab, running on OpenAI. It picks from nine read-only graph tools, from `fleet_summary` and `blast_radius` to `evidence`, `fix_plan` and `team_inbox`, plus `run_cypher` for anything the others don't cover. Every answer lists the tools it used.

The important design choice is that every query goes through `GRAPH.RO_QUERY`, so safety doesn't depend on the prompt. If the model writes a `CREATE` or `DELETE` into `run_cypher`, FalkorDB itself refuses it. `run_cypher` also gets a 5-second timeout and a 50-row cap.

The same tools are exposed as an MCP server, so you can plug the graph into your own agent:

```sh
claude mcp add --transport http clearance https://clearance-lemon.vercel.app/api/mcp
```

## A proof only counts if your scanner applies it

Nobody is going to swap out their scanner for a demo. So the test that matters is whether the "not affected" proof actually reaches the tool people already run. Trivy reads OpenVEX through `--vex`, so I ran it on all 20 repos at the same pinned commits, once without Clearance's VEX and once with it:

| `trivy fs --detection-priority comprehensive` on each go.mod | findings |
|---|---|
| without VEX | 308 |
| with Clearance's VEX | 243 (65 suppressed) |

Getting there took two fixes, and both are worth knowing if you write VEX yourself. My first VEX named the product `pkg:github/grafana/mimir@<sha>`, and Trivy matched nothing, because Trivy matches a statement against the module it scanned plus the vulnerable package. So each statement now also names `pkg:golang/github.com/grafana/mimir`, with `pkg:golang/stdlib@v1.26.7` as a subcomponent, and the pinned-commit product is still there. The second surprise was that, by default, `trivy fs` on a go.mod doesn't report standard-library vulnerabilities at all. You need `--detection-priority comprehensive` to see them.

The 65 suppressed findings are exactly the 65 that Clearance proved not affected. Repo by repo the counts match, and nothing affected or under investigation was suppressed. The numbers don't line up with 278 because Trivy counts one finding per affected package. Of its 308, 275 are the same (repo, advisory) pairs and 20 repeat one of those on another package. The last 13 are GitHub advisories with no Go vulnerability database record, such as six for kin-openapi published on Oct 15. Without the vulnerable functions there's nothing to trace, so Clearance gives those no verdict either way and says so.

## On your own repo, in CI

`npm run check` runs the same graph and the same queries on one checkout, in a throwaway graph on any FalkorDB. It runs govulncheck itself, or takes the JSON your CI already makes. It prints each affected path with its `file:line` and owning team, writes the OpenVEX file, and sets an exit code a CI job can gate on. It exits 1 when something is reachable from shipped code, 0 when nothing is, and 2 when the scan failed.

That last case caught me out. With `-format json`, govulncheck exits 0 whether or not it finds anything. A failed run can still write a valid-looking file: Beyla's failed scan is a single config line, byte for byte the same shape as a clean scan with no findings. My first version of the command would have proven Beyla safe. It now requires govulncheck's exit code, and a non-zero one means "under investigation", never "not affected". On mimir at the fleet's commit, the command gives the same 14 verdicts as the fleet graph, field for field, in about nine seconds.

Then I wired it into a GitHub Actions example that scans grafana/smtprelay on GitHub's own runners, with FalkorDB as a service container. The first real runs taught me two more things that no local test could have. First, govulncheck installed with `go install` isn't on the PATH until you add Go's bin directory. Second, govulncheck's real JSON output is a stream of indented objects, not one object per line. My parser had assumed one per line because my own scan script had compacted the output with `jq`. Now the job runs end to end. It finds 20 advisories reachable from shipped code, 7 not affected and 0 under investigation, fails the build with exit 1, and uploads the OpenVEX file as an artifact. The red build is the point: the gate caught vulnerabilities that are really reachable.

## Running on the free tier

The live demo runs on Vercel plus the free FalkorDB Cloud tier, and that tier keeps nothing across a restart. So when a request finds the graph missing, the app takes a lock, rebuilds the graph from the public sources and the committed govulncheck scans, and answers "being rebuilt" to everyone else in the meantime. I tested it by deleting the production graph myself; it was back in about a minute.

One more free-tier constraint: the Cloud user isn't allowed plain Redis commands like `INCR`, so the per-visitor rate-limit counters for the Ask tab are nodes in a separate small graph. Visitor IPs are stored only as salted hashes that expire.

## The whole fleet

| | |
|---|---|
| Alerts a version-only scanner raises (repo × advisory) | **278** |
| Proven **not affected** | **65** |
| **Affected**, each with its call path | **195** (183 from shipped code, 12 only from examples) |
| Under investigation (the scan failed, nothing claimed) | **18** |
| Pull requests that close every affected verdict | **14**, routed to **10** CODEOWNERS teams |

Sixty-five alerts that someone would otherwise have triaged by hand now come with a proof attached. The other 195 come with the line of code to look at and the name of the team that owns it.

## A bug I found in FalkorDB itself

Clearance's advisory list counts verdicts per advisory with `sum(CASE …)`, grouped by four advisory properties. On FalkorDB 6.0.2 those sums came back equal to `count()`. I worked around it by aggregating on the advisory node first, then projecting the properties, and kept building. After submitting, I went back to it.

I ran the same queries against three engines side by side: FalkorDB 6.0.2, the newest 6.x development build, and the older 4.22 C engine. It was much bigger than my one query. On the 6.x engine, any query that groups by more values than it has bound variables gets its later aggregates wrong. `MATCH (n:P) RETURN n.country, n.city, count(n), sum(n.age)` returns the count as the sum, and with `avg()` instead of `sum()` the query crashes the whole server. The 4.22 engine gets every case right.

The cause was one line. When FalkorDB finishes a group, it computes each aggregate from a row that holds the accumulators, then writes each result back into that same row. The engine numbers variables per scope, starting from zero, so a result can land in the slot where a later aggregate's accumulator still sits, and that aggregate then reads the wrong value. `avg` keeps a list as its accumulator, so when it finds a number there instead, the engine panics.

I removed the write and added a regression test. Then I built FalkorDB on a throwaway cloud VM to prove the fix. The new test fails without it, with exactly the wrong values I had predicted, and passes with it. So do FalkorDB's own end-to-end, TCK and Rust unit test suites. The bug is filed as [FalkorDB#3375](https://github.com/FalkorDB/FalkorDB/issues/3375), with the fix in [FalkorDB#3374](https://github.com/FalkorDB/FalkorDB/pull/3374).

## What I learned

Four things stuck with me. Ask the graph for the one path you need, not every path: the difference between listing paths and `shortestPath` was the difference between a crashed database and an instant answer. "I don't know" has to be a first-class answer everywhere, from failed scans to exit codes, because the most dangerous bug in a tool like this is a false "safe". A proof only matters once it lands in the tools people already use, which is why the Trivy number matters more to me than anything on my own dashboard. And when a database hands you a number that can't be right, it's worth finding out why: my one odd sum turned out to be a bug in everyday GROUP BY queries that could also crash the server.

## What it doesn't claim

Reachability is only as good as govulncheck's static analysis, and function-level data only exists for Go, which is why the fleet is Go. Standard-library verdicts assume the toolchain declared in `go.mod`, so a release pipeline that builds with a newer Go may already be fixed. The `CALLS` edges are govulncheck's evidence, the call stacks it found leading toward vulnerable code, not a full call graph. And only CODEOWNERS teams are stored; handles of individual people are dropped at ingest.

## Try it

The live fleet is at [clearance-lemon.vercel.app](https://clearance-lemon.vercel.app); open the console and pick GO-2026-6609. The code and every Cypher query are at [github.com/N-45div/clearance](https://github.com/N-45div/clearance). To run it on your own Go service:

```sh
npm run check -- --run --dir ../my-service --vex openvex.json
trivy fs --detection-priority comprehensive --vex openvex.json ../my-service
```

Built in coordination with an AI coding assistant, Claude Code.
