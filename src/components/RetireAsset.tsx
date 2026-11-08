"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "./api";

export default function RetireAsset({ assetId, redirect }: { assetId: number; redirect?: string }) {
  const router = useRouter();
  const [error, setError] = useState("");
  async function retire() {
    if (!window.confirm("Retire this asset? This is refused while it has tickets.")) return;
    try { await api("DELETE", `/api/assets/${assetId}`); if (redirect) router.push(redirect); router.refresh(); }
    catch (e) { setError((e as Error).message); }
  }
  return (
    <>
      <button className="small danger" onClick={retire}>Retire</button>
      {error && <div className="notice error" style={{ marginTop: 6 }}>{error}</div>}
    </>
  );
}
