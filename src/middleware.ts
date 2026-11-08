import { withAuth } from "next-auth/middleware";
import { NextResponse } from "next/server";
import { can, type Permission } from "@/lib/rbac";

/**
 * Page-level route guard (front-end RBAC). API routes check permissions themselves
 * and return JSON 401/403, and the databases enforce their own roles underneath.
 */
const RULES: Array<[prefix: string, permission: Permission]> = [
  ["/admin", "users:admin"],
  ["/audit", "audit:read"],
  ["/reports", "audit:read"],
  ["/tickets/new", "tickets:triage"],
  ["/cves/new", "cves:write"],
  ["/search", "search"],
];

export default withAuth(
  function middleware(req) {
    const role = req.nextauth.token?.role;
    const path = req.nextUrl.pathname;
    for (const [prefix, permission] of RULES) {
      if (path === prefix || path.startsWith(prefix + "/")) {
        if (!can(role, permission)) return NextResponse.redirect(new URL("/forbidden", req.url));
      }
    }
    return NextResponse.next();
  },
  { callbacks: { authorized: ({ token }) => !!token }, pages: { signIn: "/login" } },
);

export const config = {
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico|login|forbidden).*)"],
};
