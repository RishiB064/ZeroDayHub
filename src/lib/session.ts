import { getServerSession } from "next-auth";
import { redirect } from "next/navigation";
import { authOptions } from "./auth";
import { ApiError } from "./errors";
import { can, type Permission } from "./rbac";
import type { AppRole } from "./db/mysql";

export interface SessionUser {
  id: number;
  name: string;
  email: string;
  role: AppRole;
}

export async function currentUser(): Promise<SessionUser | null> {
  const session = await getServerSession(authOptions);
  const u = session?.user;
  if (!u?.id || !u.role) return null;
  return { id: u.id, name: u.name ?? "", email: u.email ?? "", role: u.role };
}

/** For route handlers: 401 when signed out, 403 when the role lacks the permission. */
export async function requireUser(permission?: Permission): Promise<SessionUser> {
  const user = await currentUser();
  if (!user) throw new ApiError(401, "Please sign in.");
  if (permission && !can(user.role, permission)) {
    throw new ApiError(403, "Your role is not allowed to do this.");
  }
  return user;
}

/** For server components / pages: redirect instead of throwing. */
export async function pageUser(permission?: Permission): Promise<SessionUser> {
  const user = await currentUser();
  if (!user) redirect("/login");
  if (permission && !can(user.role, permission)) redirect("/forbidden");
  return user;
}
