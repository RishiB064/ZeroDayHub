"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "./api";

interface Opt { id: number; label: string }

export default function NewTicketForm({ assets, cves, analysts, defaultAnalyst }: { assets: Opt[]; cves: { id: string; label: string }[]; analysts: Opt[]; defaultAnalyst: number }) {
  const router = useRouter();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true); setError("");
    const f = new FormData(e.currentTarget);
    try {
      await api("POST", "/api/tickets", { assetId: f.get("assetId"), cveId: f.get("cveId"), analystId: f.get("analystId") });
      router.push("/tickets"); router.refresh();
    } catch (err) { setError((err as Error).message); setBusy(false); }
  }

  return (
    <form className="card" onSubmit={submit}>
      {error && <div className="notice error">{error}</div>}
      <div className="form-grid">
        <div className="field"><label htmlFor="assetId">Asset</label>
          <select id="assetId" name="assetId" required>{assets.map((a) => <option key={a.id} value={a.id}>{a.label}</option>)}</select></div>
        <div className="field"><label htmlFor="cveId">CVE</label>
          <select id="cveId" name="cveId" required>{cves.map((c) => <option key={c.id} value={c.id}>{c.label}</option>)}</select></div>
        <div className="field"><label htmlFor="analystId">Assigned analyst</label>
          <select id="analystId" name="analystId" defaultValue={defaultAnalyst} required>{analysts.map((a) => <option key={a.id} value={a.id}>{a.label}</option>)}</select></div>
      </div>
      <p className="sub" style={{ marginTop: 12 }}>The SLA deadline is computed in the database from the CVE severity (stored procedure <code>sp_triage_ticket</code>).</p>
      <button disabled={busy}>{busy ? "Creating..." : "Create ticket"}</button>
    </form>
  );
}
