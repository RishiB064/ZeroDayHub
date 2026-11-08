"use client";

import { useState } from "react";
import { signIn } from "next-auth/react";
import { useRouter } from "next/navigation";

export interface DemoAccount { label: string; email: string }

export default function LoginForm({ demo = [], demoPassword = "" }: { demo?: DemoAccount[]; demoPassword?: string }) {
  const router = useRouter();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function login(email: string, password: string) {
    setBusy(true);
    setError("");
    const res = await signIn("credentials", { email, password, redirect: false });
    setBusy(false);
    if (!res || res.error) {
      setError("Invalid e-mail or password, or the account is locked or disabled.");
      return;
    }
    router.replace("/");
    router.refresh();
  }

  function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    void login(String(form.get("email") ?? ""), String(form.get("password") ?? ""));
  }

  return (
    <div className="grid" style={{ gap: 14 }}>
      {error && <div className="notice error" role="alert">{error}</div>}
      {demo.length > 0 && (
        <div className="grid" style={{ gap: 8 }}>
          <label>Quick sign in (demo)</label>
          {demo.map((d) => (
            <button key={d.email} type="button" className="secondary" disabled={busy} onClick={() => login(d.email, demoPassword)}>
              {d.label}
            </button>
          ))}
          <div className="sub" style={{ fontSize: 12.5, marginTop: 4 }}>or sign in with your own account</div>
        </div>
      )}
      <form onSubmit={onSubmit} className="grid" style={{ gap: 12 }}>
        <div className="field">
          <label htmlFor="email">E-mail</label>
          <input id="email" name="email" type="email" autoComplete="username" required />
        </div>
        <div className="field">
          <label htmlFor="password">Password</label>
          <input id="password" name="password" type="password" autoComplete="current-password" required />
        </div>
        <button type="submit" disabled={busy}>{busy ? "Signing in..." : "Sign in"}</button>
      </form>
    </div>
  );
}
