import { StrictMode, useCallback, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { api, type AdvisoryRow, type BlastRadius, type GraphData, type PlannedFix, type Step, type Summary, type Teams } from "./api";
import { Changes } from "./Changes";
import { Evidence } from "./Evidence";
import { Graph } from "./Graph";
import { Landing } from "./Landing";
import "./styles.css";

type Tab = "advisories" | "plan" | "teams" | "changes" | "ask";
const TABS: [Tab, string][] = [["advisories", "Advisories"], ["plan", "Fix plan"], ["teams", "Teams"], ["changes", "Changes"], ["ask", "Ask"]];

const pct = (n: number, d: number) => `${d ? (n / d) * 100 : 0}%`;
const day = (iso: string) => new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });

function Shield() {
  return (
    <svg width="26" height="26" viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5z" fill="var(--safe)" />
      <path d="m8.5 12 2.5 2.5 4.5-5" stroke="white" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function Stats({ s }: { s: Summary }) {
  return (
    <div className="stats">
      <div className="stat">
        <div className="n">{s.flagged}</div>
        <div className="l">alerts from version matching</div>
        <div className="s">{s.advisories} advisories × {s.repos} Grafana Go services</div>
      </div>
      <div className="stat safe">
        <div className="n">{s.notAffected}</div>
        <div className="l">proven not affected</div>
        <div className="s">no call path reaches the vulnerable code</div>
      </div>
      <div className="stat affected">
        <div className="n">{s.affected}</div>
        <div className="l">affected, with the call path</div>
        <div className="s">closed by {s.pullRequests} pull requests across {s.teams} teams</div>
      </div>
      <div className="stat unknown">
        <div className="n">{s.underInvestigation}</div>
        <div className="l">under investigation</div>
        <div className="s">{s.repos - s.scanned} scans failed; nothing is claimed</div>
      </div>
    </div>
  );
}

function Bar({ a }: { a: { affected: number; notAffected: number; underInvestigation: number; repos: number } }) {
  return (
    <>
      <div className="bar">
        <span className="a" style={{ width: pct(a.affected, a.repos) }} />
        <span className="s" style={{ width: pct(a.notAffected, a.repos) }} />
        <span className="u" style={{ width: pct(a.underInvestigation, a.repos) }} />
      </div>
      <div className="legend">
        <span className="a"><b>{a.affected}</b> affected</span>
        <span className="s"><b>{a.notAffected}</b> not affected</span>
        {a.underInvestigation > 0 && <span className="u"><b>{a.underInvestigation}</b> open</span>}
      </div>
    </>
  );
}

function Advisories({ list, initial }: { list: AdvisoryRow[]; initial: string }) {
  const [q, setQ] = useState("");
  const [id, setId] = useState(initial);
  const [br, setBr] = useState<BlastRadius>();
  const [graph, setGraph] = useState<GraphData>();
  const [open, setOpen] = useState<string>();

  useEffect(() => {
    setBr(undefined);
    setGraph(undefined);
    setOpen(undefined);
    api.blastRadius(id).then(setBr);
    api.graph(id).then(setGraph);
    history.replaceState(null, "", `#/advisories/${id}`);
  }, [id]);

  const shown = useMemo(() => {
    const t = q.trim().toLowerCase();
    return t ? list.filter((a) => `${a.id} ${a.summary} ${a.aliases.join(" ")}`.toLowerCase().includes(t)) : list;
  }, [q, list]);

  const onRepo = useCallback((repo: string) => {
    setOpen(repo);
    document.getElementById(`repo-${repo}`)?.scrollIntoView({ behavior: "smooth", block: "center" });
  }, []);

  return (
    <div className="split">
      <aside className="panel">
        <div className="panel-head">
          <input className="search" placeholder="Search advisories, CVEs" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="adv-list">
          {shown.map((a) => (
            <button key={a.id} className="adv" aria-current={a.id === id} onClick={() => setId(a.id)}>
              <div className="row1"><span className="id">{a.id}</span><span className="date">{day(a.published)}</span></div>
              <div className="sum">{a.summary}</div>
              <Bar a={a} />
            </button>
          ))}
          {shown.length === 0 && <p className="empty">No advisory matches.</p>}
        </div>
      </aside>
      <section className="panel detail">
        {!br ? (
          <p className="empty">Loading the blast radius…</p>
        ) : (
          <>
            <div className="meta">
              <span className="mono">{br.advisory.id}</span>
              {br.advisory.aliases.map((x) => <span key={x} className="mono">{x}</span>)}
              <span>published {day(br.advisory.published)}</span>
              <a href={br.advisory.url} target="_blank" rel="noreferrer">pkg.go.dev</a>
            </div>
            <h2>{br.advisory.summary}</h2>
            <div className="verdict-line">
              Version matching flags <b>{br.counts.flagged}</b> services. The graph proves{" "}
              <b className="s">{br.counts.notAffected} not affected</b>, routes{" "}
              <b className="a">{br.counts.affected} affected</b> to their owners
              {br.counts.examplesTestsOnly > 0 && ` (${br.counts.examplesTestsOnly} only through examples or tests)`}
              {br.counts.underInvestigation > 0 && <>, and leaves <b className="u">{br.counts.underInvestigation} under investigation</b></>}.
            </div>
            <Graph data={graph} onRepo={onRepo} />
            <div className="repos">
              {br.repos.map((r) => (
                <div key={r.repo} className="repo-row" id={`repo-${r.repo}`}>
                  <button className="repo-btn" aria-expanded={open === r.repo} onClick={() => setOpen(open === r.repo ? undefined : r.repo)}>
                    <span className="name">{r.repo}</span>
                    <span className={`badge ${r.status}`}>{r.status.replace(/_/g, " ")}</span>
                    <span className="why">
                      {r.status === "affected" && r.file ? <span className="mono">{r.file}</span> : r.reason}
                      {r.reach === "examples_tests_only" && <span className="note"> · examples/tests only</span>}
                    </span>
                    <span className="chev">
                      {r.owners.slice(0, 1).map((o) => <span key={o} className="chip">{o}</span>)} {open === r.repo ? "▾" : "▸"}
                    </span>
                  </button>
                  {open === r.repo && <Evidence advisory={id} verdict={r} />}
                </div>
              ))}
            </div>
          </>
        )}
      </section>
    </div>
  );
}

function Plan() {
  const [plan, setPlan] = useState<PlannedFix[]>();
  useEffect(() => { api.plan().then(setPlan); }, []);
  if (!plan) return <p className="empty">Loading the plan…</p>;
  const closes = plan.reduce((n, p) => n + p.advisories.length, 0);
  return (
    <section className="panel">
      <div className="panel-head">
        <h3>{plan.length} pull requests close every affected verdict</h3>
        <span className="hint">one per repo and module, bumped to the highest fix any advisory needs · {closes} verdict closures</span>
      </div>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Repo</th><th>Bump</th><th className="num">Closes</th><th>Owners</th></tr></thead>
          <tbody>
            {plan.map((p) => (
              <tr key={`${p.repo}|${p.module}`}>
                <td><b>{p.repo}</b></td>
                <td className="mono">{p.module} {p.from} → {p.to ?? "no fix yet"}</td>
                <td className="num">{p.advisories.length}</td>
                <td>{p.teams.length ? p.teams.map((t) => <span key={t} className="chip">{t}</span>) : <span className="chip muted">no CODEOWNERS team</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function TeamsView() {
  const [t, setT] = useState<Teams>();
  useEffect(() => { api.teams().then(setT); }, []);
  if (!t) return <p className="empty">Loading teams…</p>;
  return (
    <section className="panel">
      <div className="panel-head">
        <h3>Affected work by CODEOWNERS team</h3>
        <span className="hint">routed from the file that calls into the vulnerable dependency</span>
      </div>
      <div className="team-grid">
        {t.owned.map((x) => (
          <div key={x.team} className="team">
            <div className="chip">{x.team}</div>
            <div className="n">{x.verdicts}</div>
            <div className="pkg">affected verdicts in {x.repos.join(", ")}</div>
          </div>
        ))}
        {t.unowned.verdicts > 0 && (
          <div className="team">
            <div className="chip muted">no team in CODEOWNERS</div>
            <div className="n">{t.unowned.verdicts}</div>
            <div className="pkg">in {t.unowned.repos.join(", ")}</div>
          </div>
        )}
      </div>
    </section>
  );
}

// Tiny, safe markdown: escape everything, then add bold, code and lists.
function md(text: string) {
  const esc = text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const inline = (s: string) => s.replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>");
  const out: string[] = [];
  let list = false;
  for (const line of esc.split("\n")) {
    const item = /^\s*[-*]\s+(.*)$/.exec(line);
    if (item) {
      if (!list) out.push("<ul>");
      list = true;
      out.push(`<li>${inline(item[1] ?? "")}</li>`);
      continue;
    }
    if (list) out.push("</ul>");
    list = false;
    if (line.trim()) out.push(`<p>${inline(line)}</p>`);
  }
  if (list) out.push("</ul>");
  return out.join("");
}

const SUGGESTIONS = [
  "GO-2026-6609 just landed. Which services are actually affected, and who owns the fix?",
  "Which repos call into golang.org/x/net/http2 from their own code?",
  "What does @grafana/k6-core need to do this week?",
  "Why is beyla under investigation?",
];

function Ask() {
  const [thread, setThread] = useState<{ role: "user" | "assistant"; content: string; steps?: Step[] }[]>([]);
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>();

  const send = async (question: string) => {
    if (!question.trim() || busy) return;
    const history = thread.map(({ role, content }) => ({ role, content }));
    setThread((t) => [...t, { role: "user", content: question }]);
    setQ("");
    setBusy(true);
    setErr(undefined);
    try {
      const a = await api.ask(question, history);
      setThread((t) => [...t, { role: "assistant", content: a.answer, steps: a.steps }]);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel ask">
      <div className="chips">
        {SUGGESTIONS.map((s) => <button key={s} onClick={() => send(s)} disabled={busy}>{s}</button>)}
      </div>
      <div className="thread">
        {thread.length === 0 && <p className="empty">Ask about any advisory, repo or team. Every answer comes from read-only graph queries; the tools used are listed under it.</p>}
        {thread.map((m, i) =>
          m.role === "user" ? (
            <div key={i} className="msg user">{m.content}</div>
          ) : (
            <div key={i} className="msg bot">
              <div dangerouslySetInnerHTML={{ __html: md(m.content) }} />
              {m.steps && m.steps.length > 0 && (
                <div className="tools">graph tools: {m.steps.map((s) => `${s.tool}(${Object.values(s.args).join(", ").slice(0, 80)})${s.error ? " failed" : ""}`).join(" → ")}</div>
              )}
            </div>
          ),
        )}
        {busy && <div className="msg bot"><span className="pkg">Querying the graph…</span></div>}
        {err && <div className="msg bot err">{err}</div>}
      </div>
      <form className="composer" onSubmit={(e) => { e.preventDefault(); send(q); }}>
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="e.g. Which teams own code that reaches net/http.Server.Serve?" maxLength={2000} />
        <button className="btn primary" disabled={busy || !q.trim()}>Ask</button>
      </form>
    </section>
  );
}

// The console: advisories, fix plan, teams, changes and the agent.
function Console() {
  const initialTab = (location.hash.split("/")[1] as Tab) || "advisories";
  const [tab, setTab] = useState<Tab>(TABS.some(([t]) => t === initialTab) ? initialTab : "advisories");
  const [summary, setSummary] = useState<Summary>();
  const [list, setList] = useState<AdvisoryRow[]>();
  const [err, setErr] = useState<string>();

  useEffect(() => {
    api.summary().then(setSummary, (e: Error) => setErr(e.message));
    api.advisories().then(setList, (e: Error) => setErr(e.message));
  }, []);

  const go = (t: Tab) => {
    setTab(t);
    history.replaceState(null, "", `#/${t}`);
  };

  const fromHash = location.hash.startsWith("#/advisories/") ? location.hash.split("/")[2] : undefined;
  const initialAdvisory = fromHash ?? list?.find((a) => a.id === "GO-2026-6609")?.id ?? list?.[0]?.id;

  return (
    <div className="shell">
      <header className="top">
        <a className="brand" href="#/" style={{ textDecoration: "none", color: "inherit" }}>
          <Shield />
          <div>
            <h1>Clearance</h1>
            <p>Go vulnerability triage on a FalkorDB graph · Grafana fleet, pinned commits</p>
          </div>
        </a>
        <nav className="tabs" role="tablist">
          {TABS.map(([t, label]) => (
            <button key={t} role="tab" aria-selected={tab === t} onClick={() => go(t)}>{label}</button>
          ))}
        </nav>
      </header>

      <div className="lede">
        <h2>A new Go advisory lands. Which services are really affected?</h2>
        <p>Each verdict is a path in the graph: from the service's own code, through its dependencies, to the vulnerable function. No path, no alert, and the proof goes into OpenVEX.</p>
      </div>

      {err && <p className="err">{err}</p>}
      {summary && <Stats s={summary} />}

      {tab === "advisories" && list && initialAdvisory && <Advisories list={list} initial={initialAdvisory} />}
      {tab === "plan" && <Plan />}
      {tab === "teams" && <TeamsView />}
      {tab === "changes" && <Changes />}
      {tab === "ask" && <Ask />}

      <p className="foot">
        Reachability from govulncheck v1.9.0 (Go vulndb 2026-10-08) at each repo's pinned commit and declared toolchain.
        Standard-library verdicts assume that toolchain. Built for Graph Hacks 2026.
      </p>
    </div>
  );
}

// "/" (no hash, or "#/") is the landing page; every other hash route is the console.
// Console routes start with "#/"; in-page anchors such as "#faq" stay on the landing page.
const isLanding = () => !location.hash.startsWith("#/") || location.hash === "#/";

function Root() {
  const [landing, setLanding] = useState(isLanding());
  useEffect(() => {
    const onHash = () => {
      const next = isLanding();
      setLanding((prev) => {
        if (prev !== next) window.scrollTo(0, 0);
        return next;
      });
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  return landing ? <Landing /> : <Console />;
}

createRoot(document.getElementById("root")!).render(<StrictMode><Root /></StrictMode>);
