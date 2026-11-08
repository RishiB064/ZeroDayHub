import type { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import bcrypt from "bcryptjs";
import { query, type AppRole } from "./db/mysql";
import { isRole } from "./rbac";
import { loginSchema } from "./validation";

// compared against when the e-mail is unknown, so response time does not reveal which accounts exist
const DUMMY_HASH = "$2a$10$vJwmz.O6h7YA7pMlWKbtVOiI6b4ku23qWi.YS40oTAQOCgTgzhNM.";

// basic brute-force throttle: 5 failures -> 10 minute lock per e-mail (in-memory, per server instance)
const attempts = new Map<string, { count: number; lockedUntil: number }>();
const MAX_FAILS = 5;
const LOCK_MS = 10 * 60 * 1000;

function isLocked(email: string): boolean {
  const a = attempts.get(email);
  return !!a && a.lockedUntil > Date.now();
}
function recordFailure(email: string) {
  const a = attempts.get(email) ?? { count: 0, lockedUntil: 0 };
  a.count += 1;
  if (a.count >= MAX_FAILS) {
    a.lockedUntil = Date.now() + LOCK_MS;
    a.count = 0;
  }
  attempts.set(email, a);
}

interface LoginRow {
  user_id: number;
  full_name: string;
  email: string;
  password_hash: string;
  role: AppRole;
  is_active: number;
}

export const authOptions: NextAuthOptions = {
  session: { strategy: "jwt", maxAge: 60 * 60 * 8 }, // 8 hours
  pages: { signIn: "/login" },
  providers: [
    CredentialsProvider({
      name: "Email and password",
      credentials: { email: { label: "Email", type: "email" }, password: { label: "Password", type: "password" } },
      async authorize(raw) {
        const parsed = loginSchema.safeParse(raw);
        if (!parsed.success) return null;
        const { email, password } = parsed.data;
        if (isLocked(email)) return null;

        // dedicated low-privilege DB account: it can read only the login columns of `users`
        const rows = await query<LoginRow>(
          "auth",
          "SELECT user_id, full_name, email, password_hash, role, is_active FROM users WHERE email = ?",
          [email],
        );
        const user = rows[0];
        const ok = await bcrypt.compare(password, user?.password_hash ?? DUMMY_HASH);
        if (!user || !ok || !user.is_active || !isRole(user.role)) {
          recordFailure(email);
          return null;
        }
        attempts.delete(email);
        await query("auth", "UPDATE users SET last_login_at = NOW() WHERE user_id = ?", [user.user_id]);
        return { id: String(user.user_id), name: user.full_name, email: user.email, role: user.role };
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.uid = Number(user.id);
        token.role = (user as { role: AppRole }).role;
      }
      return token;
    },
    async session({ session, token }) {
      if (session.user) {
        session.user.id = token.uid as number;
        session.user.role = token.role as AppRole;
      }
      return session;
    },
  },
};
