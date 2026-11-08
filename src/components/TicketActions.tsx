"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "./api";
import { shortDate } from "./ui";

interface Props {
  ticketId: number;
  status: string;
  canPatch: boolean;
  canReview: boolean;
  canTimeline: boolean;
}
interface Entry { log_id: number; logged_at: string; action_type: string; log_message: string; actor_name: string }

export default function TicketActions({ ticketId, status, canPatch, canReview, canTimeline }: Props) {
  const router = useRouter();
  const [commit, setCommit] = useState("");
  const [msg, setMsg] = useState<{ kind: "ok" | "error"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [timeline, setTimeline] = useState<Entry[] | null>(null);

  async function act(fn: () => Promise<unknown>, ok: string) {
    setBusy(true); setMsg(null);
    try { await fn(); setMsg({ kind: "ok", text: ok }); router.refresh(); }
    catch (e) { setMsg({ kind: "error", text: (e as Error).message }); }
    finally { setBusy(false); }
  }

  async function review(verdict: "VERIFIED" | "REJECTED") {
    const notes = verdict === "REJECTED" ? window.prompt("Reason for rejection (optional)") ?? "" : "";
    await act(() => api("POST", `/api/tickets/${ticketId}/review`, { verdict, notes }), verdict === "VERIFIED" ? "Verified: ticket resolved." : "Rejected: back to OPEN.");
  }

  async function loadTimeline() {
    if (timeline) { setTimeline(null); return; }
    try { setTimeline((await api<{ events: Entry[] }>("GET", `/api/tickets/${ticketId}/timeline`)).events); }
    catch (e) { setMsg({ kind: "error", text: (e as Error).message }); }
  }

  return (
    <div>
      <div className="actions">
        {canPatch && status !== "RESOLVED" && status !== "IN_PROGRESS" && (
          <form className="inline-form" onSubmit={(e) => { e.preventDefault(); void act(() => api("POST", `/api/tickets/${ticketId}/patch`, { commitHash: commit }), "Patch submitted."); }}>
            <input value={commit} onChange={(e) => setCommit(e.target.value)} placeholder="commit hash" required aria-label="commit hash" />
            <button className="small" disabled={busy}>Submit patch</button>
          </form>
        )}
        {canReview && status === "IN_PROGRESS" && (
          <>
            <button className="small" disabled={busy} onClick={() => review("VERIFIED")}>Verify</button>
            <button className="small danger" disabled={busy} onClick={() => review("REJECTED")}>Reject</button>
          </>
        )}
        {canTimeline && <button className="small secondary" onClick={loadTimeline}>{timeline ? "Hide history" : "History"}</button>}
      </div>
      {msg && <div className={`notice ${msg.kind}`} style={{ marginTop: 8, marginBottom: 0 }}>{msg.text}</div>}
      {timeline && (
        <ul className="timeline" style={{ marginTop: 8 }}>
          {timeline.length === 0 && <li>No history.</li>}
          {timeline.map((t) => (
            <li key={t.log_id}><span className="when">{shortDate(t.logged_at)}</span> <strong>{t.action_type}</strong> by {t.actor_name}<br /><span className="small">{t.log_message}</span></li>
          ))}
        </ul>
      )}
    </div>
  );
}
