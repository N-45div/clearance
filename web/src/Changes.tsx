import { useEffect, useMemo, useState } from "react";
import { api, type Change } from "./api";

const label = (s: string) => s.replace(/_/g, " ");

type Group = { repo: string; fromSha: string; toSha: string; at: string; items: Change[] };

// Verdicts are never edited: when a repo moves to a new commit (or an advisory changes), new verdicts
// supersede the old ones. This lists those moves, newest first.
export function Changes() {
  const [rows, setRows] = useState<Change[]>();
  const [err, setErr] = useState<string>();
  const [open, setOpen] = useState<string>();
  useEffect(() => { api.changes().then(setRows, (e: Error) => setErr(e.message)); }, []);

  const groups = useMemo(() => {
    const m = new Map<string, Group>();
    for (const r of rows ?? []) {
      const k = `${r.repo}|${r.fromSha}|${r.toSha}`;
      const g = m.get(k) ?? { repo: r.repo, fromSha: r.fromSha, toSha: r.toSha, at: r.at, items: [] };
      g.items.push(r);
      m.set(k, g);
    }
    return [...m.values()].sort((a, b) => b.at.localeCompare(a.at));
  }, [rows]);

  if (err) return <p className="err">{err}</p>;
  if (!rows) return <p className="empty">Loading changes…</p>;

  return (
    <section className="panel">
      <div className="panel-head">
        <h3>What the graph re-decided</h3>
        <span className="hint">old verdicts are kept; each new one points back with SUPERSEDES</span>
      </div>
      {groups.length === 0 && <p className="empty">No verdict has been superseded yet.</p>}
      {groups.map((g) => {
        const k = `${g.repo}|${g.fromSha}|${g.toSha}`;
        const moves = new Map<string, number>();
        for (const x of g.items) moves.set(`${x.fromStatus}→${x.toStatus}`, (moves.get(`${x.fromStatus}→${x.toStatus}`) ?? 0) + 1);
        return (
          <div key={k} className="repo-row">
            <button className="change-btn" onClick={() => setOpen(open === k ? undefined : k)} aria-expanded={open === k}>
              <span className="name">{g.repo}</span>
              <span className="mono pkg">
                {g.fromSha === g.toSha ? `at ${g.toSha.slice(0, 8)}` : `${g.fromSha.slice(0, 8)} → ${g.toSha.slice(0, 8)}`}
              </span>
              <span className="moves">
                {[...moves].map(([m, n]) => {
                  const [from = "", to = ""] = m.split("→");
                  return (
                    <span key={m} className="move">
                      <b>{n}</b> <span className={`badge ${from}`}>{label(from)}</span> → <span className={`badge ${to}`}>{label(to)}</span>
                    </span>
                  );
                })}
              </span>
              <span className="pkg">{new Date(g.at).toLocaleString()} {open === k ? "▾" : "▸"}</span>
            </button>
            {open === k && (
              <div className="evidence">
                <table>
                  <thead><tr><th>Advisory</th><th>Was</th><th>Now</th><th>Why</th></tr></thead>
                  <tbody>
                    {g.items.map((x) => (
                      <tr key={x.advisory}>
                        <td className="mono">{x.advisory}</td>
                        <td><span className={`badge ${x.fromStatus}`}>{label(x.fromStatus)}</span></td>
                        <td><span className={`badge ${x.toStatus}`}>{label(x.toStatus)}</span></td>
                        <td className="pkg">{x.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        );
      })}
    </section>
  );
}
