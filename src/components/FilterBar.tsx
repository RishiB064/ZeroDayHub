"use client";

import { useRouter, usePathname, useSearchParams } from "next/navigation";
import { useState } from "react";

export interface FilterDef { name: string; label: string; type: "text" | "select"; options?: string[]; grow?: boolean }

/** GET-style filter bar: writes to the URL so server components re-query with the filters. */
export default function FilterBar({ filters }: { filters: FilterDef[] }) {
  const router = useRouter();
  const path = usePathname();
  const params = useSearchParams();
  const [vals, setVals] = useState<Record<string, string>>(() => Object.fromEntries(filters.map((f) => [f.name, params.get(f.name) ?? ""])));

  function apply(e: React.FormEvent) {
    e.preventDefault();
    const sp = new URLSearchParams();
    for (const [k, v] of Object.entries(vals)) if (v) sp.set(k, v);
    router.push(sp.size ? `${path}?${sp}` : path);
  }

  return (
    <form className="filters" onSubmit={apply}>
      {filters.map((f) => (
        <div key={f.name} className={f.grow ? "grow" : ""}>
          <label htmlFor={`f-${f.name}`}>{f.label}</label>
          {f.type === "select" ? (
            <select id={`f-${f.name}`} value={vals[f.name]} onChange={(e) => setVals({ ...vals, [f.name]: e.target.value })}>
              <option value="">All</option>
              {f.options?.map((o) => <option key={o} value={o}>{o}</option>)}
            </select>
          ) : (
            <input id={`f-${f.name}`} value={vals[f.name]} onChange={(e) => setVals({ ...vals, [f.name]: e.target.value })} />
          )}
        </div>
      ))}
      <button className="secondary" type="submit">Apply</button>
      <button className="secondary" type="button" onClick={() => { setVals(Object.fromEntries(filters.map((f) => [f.name, ""]))); router.push(path); }}>Clear</button>
    </form>
  );
}
