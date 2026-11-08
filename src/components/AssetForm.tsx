"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "./api";

const ENVS = ["Production", "Staging", "Development"];
const CRIT = ["Low", "Medium", "High", "Critical"];

interface Initial { assetId?: number; hostname?: string; ipAddress?: string; environment?: string; osVersion?: string; criticality?: string }

/** Create (no assetId) or edit (assetId) an asset. Admins may pick the owner. */
export default function AssetForm({ initial = {}, owners, onDone }: { initial?: Initial; owners?: { id: number; label: string }[]; onDone?: () => void }) {
  const router = useRouter();
  const editing = initial.assetId !== undefined;
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = e.currentTarget;
    const f = new FormData(form);
    setBusy(true); setError("");
    const body: Record<string, unknown> = {
      ipAddress: f.get("ipAddress"), environment: f.get("environment"),
      osVersion: f.get("osVersion"), criticality: f.get("criticality"),
    };
    try {
      if (editing) await api("PUT", `/api/assets/${initial.assetId}`, body);
      else {
        body.hostname = f.get("hostname");
        if (owners && f.get("ownerId")) body.ownerId = f.get("ownerId");
        await api("POST", "/api/assets", body);
        form.reset();
      }
      router.refresh(); onDone?.();
    } catch (err) { setError((err as Error).message); }
    finally { setBusy(false); }
  }

  return (
    <form onSubmit={submit}>
      {error && <div className="notice error">{error}</div>}
      <div className="form-grid">
        {!editing && <div className="field"><label htmlFor="hostname">Hostname</label><input id="hostname" name="hostname" required /></div>}
        <div className="field"><label htmlFor="ipAddress">IP address</label><input id="ipAddress" name="ipAddress" defaultValue={initial.ipAddress} placeholder="10.0.0.5" required /></div>
        <div className="field"><label htmlFor="environment">Environment</label>
          <select id="environment" name="environment" defaultValue={initial.environment ?? "Production"}>{ENVS.map((x) => <option key={x}>{x}</option>)}</select></div>
        <div className="field"><label htmlFor="criticality">Criticality</label>
          <select id="criticality" name="criticality" defaultValue={initial.criticality ?? "Medium"}>{CRIT.map((x) => <option key={x}>{x}</option>)}</select></div>
        <div className="field"><label htmlFor="osVersion">OS version</label><input id="osVersion" name="osVersion" defaultValue={initial.osVersion} /></div>
        {!editing && owners && (
          <div className="field"><label htmlFor="ownerId">Owner</label>
            <select id="ownerId" name="ownerId">{owners.map((o) => <option key={o.id} value={o.id}>{o.label}</option>)}</select></div>
        )}
      </div>
      <div style={{ marginTop: 12 }}><button disabled={busy}>{editing ? "Save changes" : "Register asset"}</button></div>
    </form>
  );
}
