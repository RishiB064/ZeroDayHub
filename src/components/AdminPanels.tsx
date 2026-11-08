"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "./api";

export function SweepButton() {
  const router = useRouter();
  const [text, setText] = useState("");
  async function go() {
    try { const r = await api<{ escalated: number }>("POST", "/api/system/sla-sweep"); setText(`${r.escalated} ticket(s) escalated.`); router.refresh(); }
    catch (e) { setText((e as Error).message); }
  }
  return <span><button className="secondary" onClick={go}>Run SLA sweep now</button>{text && <span className="small" style={{ marginLeft: 10 }}>{text}</span>}</span>;
}

export function UserToggle({ userId, isActive, role, self }: { userId: number; isActive: boolean; role: string; self: boolean }) {
  const router = useRouter();
  const [error, setError] = useState("");
  async function patch(body: Record<string, unknown>) {
    setError("");
    try { await api("PATCH", `/api/users/${userId}`, body); router.refresh(); }
    catch (e) { setError((e as Error).message); }
  }
  return (
    <div>
      <div className="actions">
        <select aria-label="role" value={role} onChange={(e) => patch({ role: e.target.value })} style={{ width: 150, padding: "3px 6px" }}>
          <option value="Security_Analyst">Security_Analyst</option><option value="Asset_Owner">Asset_Owner</option><option value="Admin">Admin</option>
        </select>
        <button className={`small ${isActive ? "danger" : "secondary"}`} disabled={self && isActive} onClick={() => patch({ isActive: !isActive })}>{isActive ? "Deactivate" : "Activate"}</button>
      </div>
      {error && <div className="notice error" style={{ marginTop: 6, marginBottom: 0 }}>{error}</div>}
    </div>
  );
}

export function NewUserForm({ departments }: { departments: { id: number; name: string }[] }) {
  const router = useRouter();
  const [error, setError] = useState("");
  const [ok, setOk] = useState("");
  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = e.currentTarget;
    const f = new FormData(form);
    setError(""); setOk("");
    try {
      await api("POST", "/api/users", { fullName: f.get("fullName"), email: f.get("email"), password: f.get("password"), role: f.get("role"), departmentId: f.get("departmentId") });
      setOk("User created. The password was bcrypt-hashed before reaching the database."); form.reset(); router.refresh();
    } catch (err) { setError((err as Error).message); }
  }
  return (
    <form onSubmit={submit}>
      {error && <div className="notice error">{error}</div>}
      {ok && <div className="notice ok">{ok}</div>}
      <div className="form-grid">
        <div className="field"><label htmlFor="fullName">Full name</label><input id="fullName" name="fullName" required /></div>
        <div className="field"><label htmlFor="email">E-mail</label><input id="email" name="email" type="email" required /></div>
        <div className="field"><label htmlFor="password">Temporary password</label><input id="password" name="password" type="password" minLength={10} required autoComplete="new-password" /></div>
        <div className="field"><label htmlFor="role">Role</label>
          <select id="role" name="role"><option value="Asset_Owner">Asset_Owner</option><option value="Security_Analyst">Security_Analyst</option><option value="Admin">Admin</option></select></div>
        <div className="field"><label htmlFor="departmentId">Department</label>
          <select id="departmentId" name="departmentId">{departments.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}</select></div>
      </div>
      <div style={{ marginTop: 12 }}><button>Create user</button></div>
    </form>
  );
}
