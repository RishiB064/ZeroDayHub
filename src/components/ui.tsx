import type { ReactNode } from "react";

export function SeverityBadge({ value }: { value: string }) {
  return <span className={`badge sev-${value}`}>{value}</span>;
}

export function StatusBadge({ value }: { value: string }) {
  return <span className={`badge st-${value}`}>{value.replace("_", " ")}</span>;
}

export function SyncBadge({ value }: { value: string }) {
  return <span className={`badge sync-${value}`}>{value}</span>;
}

export function Kpi({ label, value, tone }: { label: string; value: ReactNode; tone?: "alert" | "warn" | "good" }) {
  return (
    <div className={`card kpi ${tone ?? ""}`}>
      <div className="label">{label}</div>
      <div className="value">{value}</div>
    </div>
  );
}

export function PageHead({ title, sub, children }: { title: string; sub?: string; children?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        {sub && <div className="sub">{sub}</div>}
      </div>
      {children && <div className="actions">{children}</div>}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

/** "2026-10-25 10:46:57" -> "25 Oct 10:46" */
export function shortDate(value: unknown): string {
  if (!value) return "-";
  const d = new Date(String(value).replace(" ", "T"));
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString("en-GB", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
}

export function dueLabel(hours: number, breached: boolean): string {
  if (breached) return `${Math.abs(Math.round(hours / 24 * 10) / 10)}d overdue`;
  if (hours < 24) return `${hours}h left`;
  return `${Math.round(hours / 24)}d left`;
}
