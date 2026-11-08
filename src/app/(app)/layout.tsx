import Nav from "@/components/Nav";
import { pageUser } from "@/lib/session";

export const dynamic = "force-dynamic";

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const user = await pageUser();
  return (
    <div className="shell">
      <Nav role={user.role} name={user.name} email={user.email} />
      <main className="main">{children}</main>
    </div>
  );
}
