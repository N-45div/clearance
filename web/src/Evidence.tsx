import { useEffect, useState } from "react";
import { api, parseBump, type Evidence as Ev, type RepoVerdict } from "./api";

const JUSTIFICATION: Record<string, string> = {
  vulnerable_code_not_in_execute_path: "Vulnerable code not in execute path",
  vulnerable_code_not_present: "Vulnerable code not present",
};

export function Evidence({ advisory, verdict }: { advisory: string; verdict: RepoVerdict }) {
  const [ev, setEv] = useState<Ev>();
  const [err, setErr] = useState<string>();
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    setEv(undefined);
    setErr(undefined);
    api.evidence(verdict.repo, advisory).then(setEv, (e: Error) => setErr(e.message));
  }, [advisory, verdict.repo]);

  const copyIssue = async () => {
    const draft = await api.issue(verdict.repo, advisory);
    await navigator.clipboard.writeText(`${draft.title}\n\n${draft.body}`);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  if (err) return <div className="evidence err">{err}</div>;
  if (!ev) return <div className="evidence"><p className="empty">Reading the path from the graph…</p></div>;

  const gh = (file: string, line: number | null) =>
    `https://github.com/${ev.org}/${verdict.repo}/blob/${ev.sha}/${file}${line ? `#L${line}` : ""}`;

  return (
    <div className="evidence">
      {verdict.status === "affected" && (
        <>
          <h4>Call path, entry point to vulnerable function</h4>
          <ol className="chain">
            {ev.frames.map((f, i) => (
              <li key={f.key} className={f.file ? "own" : i === ev.frames.length - 1 ? "vuln" : ""}>
                <span className="fn">{f.name}</span>{" "}
                <span className="pkg">{f.package}</span>
                {f.file && (
                  <a className="loc mono" href={gh(f.file, f.line)} target="_blank" rel="noreferrer">
                    {f.file}:{f.line}
                  </a>
                )}
                {f.owners.length > 0 && <> {f.owners.map((o) => <span key={o} className="chip">{o}</span>)}</>}
              </li>
            ))}
          </ol>
        </>
      )}
      <h4>Verdict</h4>
      <dl className="facts">
        <dt>Status</dt>
        <dd><span className={`badge ${verdict.status}`}>{verdict.status.replace(/_/g, " ")}</span></dd>
        {verdict.justification && (<><dt>Justification</dt><dd>{JUSTIFICATION[verdict.justification] ?? verdict.justification}</dd></>)}
        <dt>Why</dt>
        <dd>{verdict.reason}</dd>
        {verdict.reach === "examples_tests_only" && (<><dt>Reach</dt><dd className="note">Only from {verdict.entryFile}: examples, tests or tooling, not shipped code. Lower priority.</dd></>)}
        <dt>{verdict.status === "affected" ? "Fix" : "In range"}</dt>
        <dd>
          {verdict.bumps.map(parseBump).map((b) => (
            <div key={b.module} className="mono">
              {b.module} {b.from}{b.to ? ` → ${b.to}` : " (no fix yet)"}
            </div>
          ))}
        </dd>
        <dt>Commit</dt>
        <dd><a className="mono" href={`https://github.com/${ev.org}/${verdict.repo}/tree/${ev.sha}`} target="_blank" rel="noreferrer">{ev.sha.slice(0, 12)}</a></dd>
        <dt>History</dt>
        <dd>
          {ev.history.map((h) => (
            <div key={h.decidedAt} className={h.current ? "" : "pkg"}>
              {h.status.replace(/_/g, " ")} · decided {new Date(h.decidedAt).toLocaleString()}
              {h.supersededAt ? ` · superseded ${new Date(h.supersededAt).toLocaleString()}` : " · current"}
            </div>
          ))}
        </dd>
      </dl>
      <div className="actions">
        {verdict.status === "affected" && (
          <button className="btn primary" onClick={copyIssue}>{copied ? "Copied" : "Copy issue draft"}</button>
        )}
        <a className="btn" href={`/api/vex/${verdict.repo}`} download>Download OpenVEX for {verdict.repo}</a>
      </div>
    </div>
  );
}
