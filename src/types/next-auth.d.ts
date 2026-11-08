import "next-auth";
import "next-auth/jwt";
import type { AppRole } from "@/lib/db/mysql";

declare module "next-auth" {
  interface Session {
    user: { id: number; name?: string | null; email?: string | null; role: AppRole };
  }
  interface User {
    role?: AppRole;
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    uid?: number;
    role?: AppRole;
  }
}
