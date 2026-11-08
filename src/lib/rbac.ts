import type { AppRole } from "./db/mysql";

/**
 * Application-level permission matrix. This is the SECOND line of defence:
 * the database accounts enforce the same rules independently (MySQL roles +
 * PostgreSQL roles), so a bug here cannot grant more than the DB allows.
 */
export type Permission =
  | "dashboard"
  | "tickets:read"
  | "tickets:triage"
  | "tickets:review"
  | "tickets:patch"
  | "assets:manage"
  | "assets:read-all"
  | "cves:read"
  | "cves:write"
  | "search"
  | "audit:read"
  | "users:admin"
  | "system:sweep";

const MATRIX: Record<AppRole, Permission[]> = {
  Security_Analyst: [
    "dashboard", "tickets:read", "tickets:triage", "tickets:review",
    "assets:read-all", "cves:read", "cves:write", "search", "audit:read",
  ],
  Asset_Owner: ["dashboard", "tickets:read", "tickets:patch", "assets:manage", "cves:read", "search"],
  Admin: [
    "dashboard", "tickets:read", "tickets:triage", "tickets:review", "tickets:patch",
    "assets:manage", "assets:read-all", "cves:read", "cves:write", "search", "audit:read",
    "users:admin", "system:sweep",
  ],
};

export const ROLES: AppRole[] = ["Security_Analyst", "Asset_Owner", "Admin"];

export function isRole(value: unknown): value is AppRole {
  return typeof value === "string" && (ROLES as string[]).includes(value);
}

export function can(role: AppRole | undefined | null, permission: Permission): boolean {
  return !!role && MATRIX[role].includes(permission);
}

export const ROLE_LABEL: Record<AppRole, string> = {
  Security_Analyst: "Security Analyst",
  Asset_Owner: "Asset Owner",
  Admin: "Administrator",
};
