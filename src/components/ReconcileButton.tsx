"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "./api";

export default function ReconcileButton() {
  const router = useRouter();
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  async function go() {
    setBusy(true); setText("");
    try {
      const r = await api<{ synced: number; failed: number; skipped: number; orphansRemoved: number }>("POST", "/api/cves/reconcile");
      setText(`Synced ${r.synced}, failed ${r.failed}, skipped ${r.skipped}, orphan vectors removed ${r.orphansRemoved}.`);
      router.refresh();
    } catch (e) { setText((e as Error).message); }
    finally { setBusy(false); }
  }
  return <span><button className="secondary" disabled={busy} onClick={go}>{busy ? "Reconciling..." : "Reconcile MySQL ↔ vectors"}</button>{text && <span className="small" style={{ marginLeft: 10 }}>{text}</span>}</span>;
}
