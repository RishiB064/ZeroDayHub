"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "./api";

export interface CveInitial {
  cveId?: string; title?: string; cweId?: string; cvssScore?: number; publishedDate?: string;
  advisoryText?: string; exploitSummary?: string; remediationPlaybook?: string; vendor?: string; product?: string; tags?: string[];
}

interface SyncInfo { sync: { status: string; action?: string; warning?: string } }

export default function CveForm({ initial = {}, cwes, editing }: { initial?: CveInitial; cwes: { id: string; name: string }[]; editing: boolean }) {
  const router = useRouter();
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const body: Record<string, unknown> = {
      title: f.get("title"), cweId: f.get("cweId"), cvssScore: f.get("cvssScore"), publishedDate: f.get("publishedDate"),
      advisoryText: f.get("advisoryText"), exploitSummary: f.get("exploitSummary"), remediationPlaybook: f.get("remediationPlaybook"),
      vendor: f.get("vendor"), product: f.get("product"),
      tags: String(f.get("tags") ?? "").split(",").map((t) => t.trim()).filter(Boolean),
    };
    setBusy(true); setError(""); setNote("");
    try {
      let res: SyncInfo;
      if (editing) res = await api<SyncInfo>("PUT", `/api/cves/${initial.cveId}`, body);
      else res = await api<SyncInfo>("POST", "/api/cves", { ...body, cveId: f.get("cveId") });
      if (res.sync.status === "FAILED") { setNote(`Saved in MySQL, but the vector copy failed: ${res.sync.warning}. Use "Re-sync" later.`); router.refresh(); }
      else { router.push(`/cves/${editing ? initial.cveId : String(f.get("cveId"))}`); router.refresh(); }
    } catch (err) { setError((err as Error).message); }
    finally { setBusy(false); }
  }

  return (
    <form className="card" onSubmit={submit}>
      {error && <div className="notice error">{error}</div>}
      {note && <div className="notice warn">{note}</div>}
      <div className="form-grid">
        <div className="field"><label htmlFor="cveId">CVE id</label><input id="cveId" name="cveId" defaultValue={initial.cveId} placeholder="CVE-2026-12345" disabled={editing} required /></div>
        <div className="field wide"><label htmlFor="title">Title</label><input id="title" name="title" defaultValue={initial.title} required /></div>
        <div className="field"><label htmlFor="cweId">Weakness (CWE)</label>
          <select id="cweId" name="cweId" defaultValue={initial.cweId}>{cwes.map((c) => <option key={c.id} value={c.id}>{c.id} · {c.name}</option>)}</select></div>
        <div className="field"><label htmlFor="cvssScore">CVSS score</label><input id="cvssScore" name="cvssScore" type="number" step="0.1" min="0" max="10" defaultValue={initial.cvssScore} required /></div>
        <div className="field"><label htmlFor="publishedDate">Published</label><input id="publishedDate" name="publishedDate" type="date" defaultValue={initial.publishedDate} required /></div>
        <div className="field"><label htmlFor="vendor">Vendor</label><input id="vendor" name="vendor" defaultValue={initial.vendor} /></div>
        <div className="field"><label htmlFor="product">Product</label><input id="product" name="product" defaultValue={initial.product} /></div>
        <div className="field"><label htmlFor="tags">Tags (comma separated)</label><input id="tags" name="tags" defaultValue={initial.tags?.join(", ")} /></div>
        <div className="field wide"><label htmlFor="advisoryText">Advisory text (this is what gets embedded)</label><textarea id="advisoryText" name="advisoryText" defaultValue={initial.advisoryText} required /></div>
        <div className="field wide"><label htmlFor="exploitSummary">Exploit summary</label><textarea id="exploitSummary" name="exploitSummary" defaultValue={initial.exploitSummary} /></div>
        <div className="field wide"><label htmlFor="remediationPlaybook">Remediation playbook</label><textarea id="remediationPlaybook" name="remediationPlaybook" defaultValue={initial.remediationPlaybook} /></div>
      </div>
      <div style={{ marginTop: 14 }}><button disabled={busy}>{busy ? "Saving and embedding..." : editing ? "Save and re-embed" : "Create CVE"}</button></div>
    </form>
  );
}
