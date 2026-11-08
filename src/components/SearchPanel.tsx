"use client";

import Link from "next/link";
import { useState } from "react";
import { api } from "./api";
import { SeverityBadge } from "./ui";
import type { SearchResponse } from "@/lib/services/search";

const EXAMPLES = [
  "attacker can run arbitrary commands on the server through a file upload",
  "login bypass by manipulating a token",
  "database query built from user input leaks records",
];

export default function SearchPanel(_props: { canSeeTickets?: boolean }) {
  const [res, setRes] = useState<SearchResponse | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [text, setText] = useState("");

  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true); setError("");
    const body: Record<string, unknown> = { query: text, k: 5, mode: "hybrid" };
    try { setRes(await api<SearchResponse>("POST", "/api/search", body)); }
    catch (err) { setError((err as Error).message); setRes(null); }
    finally { setBusy(false); }
  }

  return (
    <>
      <form className="card" onSubmit={submit}>
        <label htmlFor="q">Describe the vulnerability or the symptom in your own words</label>
        <textarea id="q" value={text} onChange={(e) => setText(e.target.value)} required minLength={3} placeholder="e.g. attacker can read other users' data by changing an id in the URL" />
        <div className="small" style={{ margin: "6px 0 12px" }}>
          Try: {EXAMPLES.map((x) => <button type="button" key={x} className="tag" style={{ border: 0, cursor: "pointer" }} onClick={() => setText(x)}>{x}</button>)}
        </div>
        <div style={{ marginTop: 12 }}><button disabled={busy}>{busy ? "Searching..." : "Search"}</button></div>
      </form>

      {error && <div className="notice error" style={{ marginTop: 14 }}>{error}</div>}
      {res?.results.map((r) => (
        <div className="card result" key={r.cveId}>
          <div className="result-head">
            <div>
              <span className="small"><Link href={`/cves/${r.cveId}`}>{r.cveId}</Link></span>
              <h2>{r.title}</h2>
            </div>
            <div style={{ textAlign: "right" }}>
              <SeverityBadge value={r.severity} />
              <div className="small" style={{ marginTop: 6 }}>{(r.similarity * 100).toFixed(0)}% match</div>
            </div>
          </div>
          <p>{r.advisoryText}</p>
          {(r.exploitSummary || r.remediationPlaybook) && (
            <details>
              <summary>Exploit and remediation</summary>
              {r.exploitSummary && <p>{r.exploitSummary}</p>}
              {r.remediationPlaybook && <div className="playbook">{r.remediationPlaybook}</div>}
            </details>
          )}
        </div>
      ))}
    </>
  );
}
