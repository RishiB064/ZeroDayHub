import bcrypt from "bcryptjs";
import { query, run, runSlaSweep, type Row } from "../db/mysql";
import type { SessionUser } from "../session";
import { ApiError } from "../errors";
import { z } from "zod";
import { userCreateSchema, userPatchSchema } from "../validation";

export type UserCreate = z.infer<typeof userCreateSchema>;
export type UserPatch = z.infer<typeof userPatchSchema>;

// ---- audit trail (analyst + admin) -----------------------------------------
export interface AuditFilters { ticketId?: number; action?: string; limit?: number }

export async function listAudit(user: SessionUser, f: AuditFilters = {}): Promise<Row[]> {
  const where: string[] = [];
  const params: unknown[] = [];
  if (f.ticketId) { where.push("ticket_id = ?"); params.push(f.ticketId); }
  if (f.action) { where.push("action_type = ?"); params.push(f.action); }
  params.push(Math.min(Math.max(f.limit ?? 100, 1), 500));
  return query(
    user.role,
    `SELECT * FROM v_audit_trail ${where.length ? "WHERE " + where.join(" AND ") : ""}
      ORDER BY logged_at DESC, log_id DESC LIMIT ?`,
    params,
  );
}

export async function auditActions(user: SessionUser): Promise<string[]> {
  const rows = await query<{ action_type: string }>(user.role, "SELECT DISTINCT action_type FROM audit_logs ORDER BY action_type");
  return rows.map((r) => r.action_type);
}

// ---- users (admin) ------------------------------------------------------------
export async function listUsers(user: SessionUser): Promise<Row[]> {
  return query(user.role, "SELECT * FROM v_user_directory ORDER BY FIELD(role,'Admin','Security_Analyst','Asset_Owner'), full_name");
}

export async function listDepartments(user: SessionUser): Promise<Row[]> {
  return query(user.role, "SELECT department_id, name FROM departments ORDER BY name");
}

export async function createUser(user: SessionUser, input: UserCreate) {
  const hash = await bcrypt.hash(input.password, 10); // salted bcrypt; the DB CHECK rejects anything else
  const res = await run(
    user.role,
    "INSERT INTO users (full_name, email, password_hash, role, department_id) VALUES (?, ?, ?, ?, ?)",
    [input.fullName, input.email, hash, input.role, input.departmentId],
  );
  return { userId: res.insertId };
}

export async function patchUser(user: SessionUser, userId: number, patch: UserPatch) {
  const sets: string[] = [];
  const params: unknown[] = [];
  if (patch.isActive !== undefined) { sets.push("is_active = ?"); params.push(patch.isActive); }
  if (patch.role !== undefined) { sets.push("role = ?"); params.push(patch.role); }
  if (!sets.length) throw new ApiError(400, "Nothing to update.");
  params.push(userId);
  const res = await run(user.role, `UPDATE users SET ${sets.join(", ")} WHERE user_id = ?`, params);
  if (!res.affectedRows) throw new ApiError(404, "User not found.");
  return { userId };
}

// ---- lookups for forms -------------------------------------------------------------
export async function listAnalysts(user: SessionUser): Promise<Row[]> {
  return query(user.role, "SELECT user_id, full_name FROM v_user_directory WHERE is_active AND role IN ('Security_Analyst','Admin') ORDER BY full_name");
}

export async function listOwners(user: SessionUser): Promise<Row[]> {
  return query(user.role, "SELECT user_id, full_name, department FROM v_user_directory WHERE is_active AND role IN ('Asset_Owner','Admin') ORDER BY full_name");
}

// ---- system -------------------------------------------------------------------------
export async function slaSweep() {
  return { escalated: await runSlaSweep() };
}
