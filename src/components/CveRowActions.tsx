"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "./api";

/** Re-sync + delete/retire controls for one CVE. */
export default function CveRowActions({ cveId, canWrite, redirect }: { cveId: string; canWrite: boolean; redirect?: string }) {
  const router = useRouter();
  const [msg, setMsg] = useState<{ kind: "ok" | "error"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  if (!canWrite) return null;

  async function run(fn: () => Promise<string>) {
    setBusy(true); setMsg(null);
    try { const text = await fn(); setMsg({ kind: "ok", text }); router.refresh(); if (redirect) router.push(redirect); }
    catch (e) { setMsg({ kind: "error", text: (e as Error).message }); }
    finally { setBusy(false); }
  }

  return (
    <div>
      <div className="actions">
        <button className="small secondary" disabled={busy} onClick={() => run(async () => {
          const r = await api<{ status: string; warning?: string }>("POST", `/api/cves/${cveId}/sync`);
          if (r.status === "FAILED") throw new Error(r.warning ?? "sync failed");
          return "Vector re-synced.";
        })}>Re-sync</button>
        <button className="small danger" disabled={busy} onClick={() => {
          if (!window.confirm(`Delete ${cveId}? CVEs with tickets are retired instead.`)) return;
          void run(async () => {
            const r = await api<{ mode: string }>("DELETE", `/api/cves/${cveId}`);
            return r.mode === "retired" ? "Retired (kept for audit history)." : "Deleted from both databases.";
          });
        }}>Delete</button>
      </div>
      {msg && <div className={`notice ${msg.kind}`} style={{ marginTop: 6, marginBottom: 0 }}>{msg.text}</div>}
    </div>
  );
}
