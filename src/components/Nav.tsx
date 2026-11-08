"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { signOut } from "next-auth/react";
import { can, ROLE_LABEL } from "@/lib/rbac";
import type { AppRole } from "@/lib/db/mysql";

interface Item { href: string; label: string; show: boolean; section?: string }

export default function Nav({ role, name, email }: { role: AppRole; name: string; email: string }) {
  const path = usePathname();
  const items: Item[] = [
    { href: "/", label: "Home", show: true },
    { href: "/tickets", label: "Tickets", show: can(role, "tickets:read") },
    { href: "/assets", label: "Assets", show: can(role, "tickets:read") },
    { href: "/cves", label: "Advisories", show: can(role, "cves:read") },
    { href: "/search", label: "Search", show: can(role, "search") },
    { href: "/reports", label: "Reports", show: can(role, "audit:read"), section: "More" },
    { href: "/admin", label: "Users", show: can(role, "users:admin") },
  ];
  const active = (href: string) => (href === "/" ? path === "/" : path === href || path.startsWith(href + "/"));

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark">Z</div>
        ZeroDayHub
      </div>
      <nav className="nav">
        {items.filter((i) => i.show).map((i) => (
          <span key={i.href}>
            {i.section && <div className="section">{i.section}</div>}
            <Link href={i.href} className={active(i.href) ? "active" : ""}>{i.label}</Link>
          </span>
        ))}
      </nav>
      <div className="user">
        <div className="name">{name}</div>
        <div className="email">{email}</div>
        <div style={{ margin: "8px 0" }}><span className="badge role-badge">{ROLE_LABEL[role]}</span></div>
        <button className="secondary small" onClick={() => signOut({ callbackUrl: "/login" })}>Sign out</button>
      </div>
    </aside>
  );
}
