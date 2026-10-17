import { useEffect, useState, type ReactNode } from "react";
import { api, parseBump, type BlastRadius, type Evidence, type GraphData, type Summary } from "./api";
import { Graph } from "./Graph";
import "./landing.css";

// Everything on this page that looks like product output is fetched from the live API.
const DEMO = "GO-2026-6609";
const CTA = "Open the live fleet";
const APP = `#/advisories/${DEMO}`;
const REPO = "https://github.com/N-45div/clearance";

type VexStatement = { vulnerability: { name: string }; products: { "@id": string }[]; status: string; justification?: string };

function Section({ id, kicker, title, lede, children }: { id?: string; kicker?: string; title: ReactNode; lede?: ReactNode; children?: ReactNode }) {
  return (
    <section className="lp-section" id={id}>
      <div className="lp-wrap">
        <div className="lp-head">
          {kicker && <div className="lp-kicker" style={{ marginBottom: 14 }}>{kicker}</div>}
          <h2>{title}</h2>
          {lede && <p className="lp-lede">{lede}</p>}
        </div>
        {children}
      </div>
    </section>
  );
}

const Pill = () => <a className="lp-pill" href={APP}>{CTA}</a>;
const Shield = () => (
  <svg width="22" height="22" viewBox="0 0 24 24" aria-hidden="true">
    <path d="M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5z" fill="var(--safe)" />
    <path d="m8.5 12 2.5 2.5 4.5-5" stroke="white" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);
const label = (s: string) => s.replace(/_/g, " ");

function AffectedPane({ ev, advisory }: { ev: Evidence | undefined; advisory: string }) {
  if (!ev) return <div className="lp-glass lp-skeleton">Reading the call path from the graph…</div>;
  const bump = ev.v.bumps.map(parseBump)[0];
  const owner = ev.v.owners[0];
  return (
    <div className="lp-glass">
      <div className="lp-pane-head">
        <span className="lp-pane-title">{ev.v.key.split("|")[0]} · <span className="lp-mono">{advisory}</span></span>
        <span className="lp-tag affected">affected</span>
      </div>
      <ul className="lp-path">
        {ev.frames.map((f, i) => (
          <li key={f.key} className={i === ev.frames.length - 1 ? "vuln" : ""}>
            {f.name}{f.file && <span className="loc"> {f.file}:{f.line}</span>}
            {!f.file && <span style={{ color: "var(--muted)" }}> {f.package}</span>}
          </li>
        ))}
      </ul>
      <dl className="lp-facts">
        {owner && (<><dt>Owner</dt><dd className="lp-mono">{owner}</dd></>)}
        {bump && (<><dt>Fix</dt><dd className="lp-mono">{bump.module === "stdlib" ? "go" : bump.module} {bump.from} → {bump.to}</dd></>)}
        <dt>Commit</dt><dd className="lp-mono">{ev.sha.slice(0, 12)}</dd>
      </dl>
    </div>
  );
}

function SafePane({ br }: { br: BlastRadius | undefined }) {
  const r = br?.repos.find((x) => x.status === "not_affected");
  if (!r) return <div className="lp-glass lp-skeleton">Reading the proof from the graph…</div>;
  return (
    <div className="lp-glass">
      <div className="lp-pane-head">
        <span className="lp-pane-title">{r.repo} · <span className="lp-mono">{br!.advisory.id}</span></span>
        <span className="lp-tag not_affected">not affected</span>
      </div>
      <p className="lp-small" style={{ color: "var(--ink)" }}>{r.reason}.</p>
      <dl className="lp-facts">
        <dt>Justification</dt><dd className="lp-mono">{r.justification}</dd>
        <dt>Version</dt><dd className="lp-mono">{r.bumps.map(parseBump).map((b) => `${b.module === "stdlib" ? "go" : b.module} ${b.from}`).join(", ")} is in range</dd>
        <dt>Commit</dt><dd className="lp-mono">{r.sha.slice(0, 12)}</dd>
      </dl>
    </div>
  );
}

function VexStrip({ stmt }: { stmt: VexStatement | undefined }) {
  if (!stmt) return null;
  return (
    <pre className="lp-code" aria-label="OpenVEX statement">
      {"{ "}<span className="k">"vulnerability"</span>: {"{ "}<span className="k">"name"</span>: <span className="s">"{stmt.vulnerability.name}"</span>{" }, "}
      <span className="k">"products"</span>: [{"{ "}<span className="k">"@id"</span>: <span className="s">"{stmt.products[0]?.["@id"]}"</span>{" }], "}
      <span className="k">"status"</span>: <span className="s">"{stmt.status}"</span>, <span className="k">"justification"</span>: <span className="s">"{stmt.justification}"</span>{" }"}
    </pre>
  );
}

const CALL_PATH = `MATCH (:Advisory {id: $advisory})-[:VULNERABLE_FUNC]->(:Func)
      <-[:IS]-(t:Frame {repo: $repo, vulnerable: true})
MATCH (:Repo {name: $repo})-[:ENTRY]->(e:Frame)
WITH e, shortestPath((e)-[:CALLS*1..30]->(t)) AS p
WHERE p IS NOT NULL
RETURN [n IN nodes(p) | n.func] AS path
ORDER BY length(p) LIMIT 1`;

const FAQ: [string, string][] = [
  ["Why not just run govulncheck?", "govulncheck answers for one module at a time. Clearance keeps its call chains for the whole fleet in one graph, then answers fleet questions: which services an advisory reaches, which team owns the calling file, which bump closes the most verdicts, and what changed since the last commit."],
  ["Why only Go?", "Function-level vulnerability data exists for Go: the Go vulnerability database lists the affected symbols. For PyPI, npm and Maven those fields are empty, so a call-path verdict would be a guess."],
  ["What does \"under investigation\" mean?", "Nothing is claimed. Either the reachability scan of that commit failed (Alloy ran out of memory, Beyla needs generated code), the repo moved to a commit that has not been scanned yet, or the advisory is newer than the scan."],
  ["What data does it use?", "Public data only: Grafana's repositories at pinned commits, OSV, the Go vulnerability database, and CODEOWNERS. Only team handles are kept; entries for individual people are dropped."],
  ["Does it open issues on my repositories?", "No. It drafts the issue, with the call path linked to the pinned commit and the owning team, for you to copy. Nothing is posted anywhere."],
  ["How does it stay current?", "A daily job loads new Go advisories that touch the fleet. When a repo moves to a new commit, its verdicts are superseded, not edited, so the history of what was decided and on which commit stays in the graph."],
];

export function Landing() {
  const [s, setS] = useState<Summary>();
  const [br, setBr] = useState<BlastRadius>();
  const [ev, setEv] = useState<Evidence>();
  const [graph, setGraph] = useState<GraphData>();
  const [stmt, setStmt] = useState<VexStatement>();
  const [tools, setTools] = useState<string[]>();
  const [err, setErr] = useState<string>();

  useEffect(() => {
    document.title = "Clearance: which Go services a vulnerability really reaches";
    api.summary().then(setS, (e: Error) => setErr(e.message));
    api.blastRadius(DEMO).then((b) => {
      setBr(b);
      const affected = b.repos.find((r) => r.status === "affected" && r.reach === "shipped") ?? b.repos.find((r) => r.status === "affected");
      if (affected) api.evidence(affected.repo, DEMO).then(setEv, () => {});
      const safe = b.repos.find((r) => r.status === "not_affected");
      if (safe) {
        fetch(`/api/vex/${safe.repo}`).then((r) => r.json()).then((doc: { statements: VexStatement[] }) =>
          setStmt(doc.statements.find((x) => x.vulnerability.name === DEMO)), () => {});
      }
    }, (e: Error) => setErr(e.message));
    api.graph(DEMO).then(setGraph, () => {});
    fetch("/api/mcp", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) })
      .then((r) => r.json()).then((j: { result?: { tools: { name: string }[] } }) => setTools(j.result?.tools.map((t) => t.name)), () => {});
  }, []);

  const mcpUrl = `${location.origin}/api/mcp`;
  const history = ev?.history ?? [];

  return (
    <div className="lp">
      <header className="lp-nav">
        <div className="lp-wrap">
          <a className="lp-logo" href="#/"><Shield /> Clearance</a>
          <nav className="lp-links">
            <a href="#how" className="hide-sm">How it works</a>
            <a href="#outputs" className="hide-sm">Outputs</a>
            <a href="#faq" className="hide-sm">FAQ</a>
            <a href="/blog" className="hide-sm">Blog</a>
            <a href={REPO} target="_blank" rel="noreferrer">GitHub</a>
            <Pill />
          </nav>
        </div>
      </header>

      <main>
        <section className="lp-section lp-hero">
          <div className="lp-wrap">
            <h1>A Go vulnerability lands.<br />Know which services it really reaches.</h1>
            <p className="lp-lede">
              Clearance follows each service's own code through its dependencies to the vulnerable function, in a FalkorDB graph.
              A path means affected, with the file, the line and the team that owns it. No path means not affected, with the proof.
            </p>
            <div className="lp-actions">
              <Pill />
              <a className="lp-textlink" href={REPO} target="_blank" rel="noreferrer">Read the code on GitHub →</a>
            </div>
            <div className="lp-frame" style={{ marginTop: 44 }}>
              {err && <div className="lp-glass lp-skeleton">{err}</div>}
              <div className="lp-grid-2">
                <AffectedPane ev={ev} advisory={DEMO} />
                <SafePane br={br} />
              </div>
              <div style={{ marginTop: 16 }}><VexStrip stmt={stmt} /></div>
            </div>
            <p className="lp-small" style={{ marginTop: 12 }}>
              Live from the graph: {DEMO}{br ? `, ${br.advisory.summary.toLowerCase()}` : ""}, across Grafana's open-source Go services.
            </p>
          </div>
        </section>

        <div className="lp-wrap">
          <div className="lp-strip">
            <span>FalkorDB</span><span>govulncheck</span><span>OSV</span><span>Go vulnerability database</span><span>OpenVEX</span><span>CODEOWNERS</span><span>MCP</span>
          </div>
        </div>

        <Section
          id="verdicts"
          title="Fewer alerts, each with a reason"
          lede={s ? `${s.advisories} advisories reach ${s.repos} Grafana Go services by version. A version-only scanner raises every pair. Clearance decides each one.` : "Reading the fleet…"}
        >
          <div className="lp-frame">
            <div className="lp-grid-4">
              <div className="lp-glass"><div className="lp-num">{s?.flagged ?? "…"}</div><div className="lp-small">alerts from version matching</div></div>
              <div className="lp-glass"><div className="lp-num safe">{s?.notAffected ?? "…"}</div><div className="lp-small">proven not affected: no call path</div></div>
              <div className="lp-glass"><div className="lp-num affected">{s?.affected ?? "…"}</div><div className="lp-small">affected, each with its call path</div></div>
              <div className="lp-glass"><div className="lp-num unknown">{s?.underInvestigation ?? "…"}</div><div className="lp-small">under investigation: nothing claimed</div></div>
            </div>
            {s && <p className="lp-small" style={{ marginTop: 16, color: "var(--ink)" }}>The {s.affected} affected verdicts close with {s.pullRequests} pull requests, routed to {s.teams} CODEOWNERS teams.</p>}
          </div>
        </Section>

        <Section id="how" title="How a verdict is made">
          <div className="lp-grid-3">
            <div>
              <div className="lp-kicker">01 Map</div>
              <h3 style={{ margin: "10px 0 8px" }}>The fleet as a graph</h3>
              <p className="lp-small">Each service at a pinned commit, the module versions it builds with, the advisories OSV matches, and the CODEOWNERS teams.</p>
            </div>
            <div>
              <div className="lp-kicker">02 Walk</div>
              <h3 style={{ margin: "10px 0 8px" }}>A path, or proof of none</h3>
              <p className="lp-small">govulncheck's call chains become frames in FalkorDB. shortestPath walks from each entry point to the vulnerable call, inside one service.</p>
            </div>
            <div>
              <div className="lp-kicker">03 Hand off</div>
              <h3 style={{ margin: "10px 0 8px" }}>To the team that owns it</h3>
              <p className="lp-small">Affected goes to the team that owns the calling file, with the version to bump to. Not affected becomes an OpenVEX statement.</p>
            </div>
          </div>
        </Section>

        <Section id="graph" title="Every answer is a query you can run" lede="The verdict is the result of a graph query, not a model's opinion. This is the advisory above, straight from FalkorDB.">
          <div className="lp-frame">
            <div className="lp-grid-2" style={{ alignItems: "stretch" }}>
              <div className="lp-glass" style={{ padding: 8 }}><Graph data={graph} onRepo={() => { location.hash = APP; }} /></div>
              <div className="lp-stack">
                <pre className="lp-code" style={{ margin: 0 }}>{CALL_PATH}</pre>
                <p className="lp-small">Frames belong to one service, so a walk never leaves it. No path from any entry point means the vulnerable code is not in the execute path.</p>
              </div>
            </div>
          </div>
        </Section>

        <Section id="outputs" title="It keeps up, and it hands off" lede="Verdicts are superseded, never edited, so the graph remembers what was decided on which commit.">
          <div className="lp-grid-3">
            <div className="lp-glass">
              <div className="lp-kicker">History</div>
              {history.length > 1 ? (
                <>
                  <div className="lp-chain">
                    {[...history].reverse().map((h, i) => (
                      <span key={h.decidedAt} style={{ display: "contents" }}>
                        {i > 0 && <span className="arrow">→</span>}
                        <span className={`lp-tag ${h.status}`}>{label(h.status)}</span>
                        <span className="lp-mono" style={{ color: "var(--muted)" }}>@{h.repoSha.slice(0, 8)}</span>
                      </span>
                    ))}
                  </div>
                  <p className="lp-small" style={{ marginTop: 8 }}>{ev?.v.key.split("|")[0]} moved to a new commit. Its verdicts waited for a rescan instead of guessing, then were decided again.</p>
                </>
              ) : (
                <p className="lp-small" style={{ marginTop: 8 }}>When a service moves to a new commit, its verdicts wait for a rescan, then are decided again.</p>
              )}
            </div>
            <div className="lp-glass">
              <div className="lp-kicker">OpenVEX + issues</div>
              <p className="lp-small" style={{ marginTop: 8 }}>One OpenVEX document per service, with a justification for every "not affected". An issue draft per affected verdict, with the call path linked to the pinned commit. Drafts are copied, never posted.</p>
            </div>
            <div className="lp-glass">
              <div className="lp-kicker">Agents</div>
              <p className="lp-small" style={{ marginTop: 8 }}>Ask in plain words, or plug the graph into your own agent over MCP. Every tool is a read-only query.</p>
              <pre className="lp-code" style={{ marginTop: 10, fontSize: 11.5 }}>claude mcp add --transport http clearance {mcpUrl}</pre>
              {tools && <p className="lp-small" style={{ marginTop: 8 }}>{tools.length} tools: {tools.join(", ")}</p>}
            </div>
          </div>
        </Section>

        <Section id="limits" title="What it does not claim">
          <div className="lp-grid-2">
            <p className="lp-small">Reachability is as good as govulncheck's static analysis, and function-level data exists only for Go.</p>
            <p className="lp-small">Standard-library verdicts assume the Go toolchain each go.mod declares; a newer release build may already be fixed.</p>
            <p className="lp-small">A path that starts only in examples, tests or tooling is marked as such and ranked lower.</p>
            <p className="lp-small">A failed or missing scan is reported as under investigation, never as safe.</p>
          </div>
        </Section>

        <section className="lp-section" id="faq">
          <div className="lp-wrap lp-faq">
            <div><h2>Questions</h2><p className="lp-lede">Short answers. The README has the graph model and every query.</p></div>
            <div>
              {FAQ.map(([q, a]) => (
                <details key={q}><summary>{q}</summary><p>{a}</p></details>
              ))}
            </div>
          </div>
        </section>

        <section className="lp-section">
          <div className="lp-wrap">
            <div className="lp-frame lp-close">
              <h2>See every verdict and its path</h2>
              <p className="lp-lede">Twenty Grafana Go services, fifty advisories, every decision explained.</p>
              <div className="lp-actions"><Pill /></div>
            </div>
          </div>
        </section>
      </main>

      <footer className="lp-wrap lp-foot">
        <span>Clearance · MIT · built for Graph Hacks (WeMakeDevs × FalkorDB), October 2026</span>
        <nav>
          <a href={REPO} target="_blank" rel="noreferrer">GitHub</a>
          <a href={`${REPO}#readme`} target="_blank" rel="noreferrer">README</a>
          <a href="/blog">Blog</a>
          <a href={APP}>The fleet</a>
        </nav>
      </footer>
    </div>
  );
}
