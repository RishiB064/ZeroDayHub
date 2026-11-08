import { redirect } from "next/navigation";
import LoginForm from "@/components/LoginForm";
import { currentUser } from "@/lib/session";

export const dynamic = "force-dynamic";

const DEMO = [
  { label: "Rishi: Administrator", email: "rishi.admin@zerodayhub.io" },
  { label: "Saathvik: Security Analyst", email: "saathvik.sec@zerodayhub.io" },
  { label: "Snigdha: Asset Owner", email: "snigdha.payments@zerodayhub.io" },
];

export default async function LoginPage() {
  if (await currentUser()) redirect("/");
  const showDemo = process.env.SHOW_DEMO_ACCOUNTS === "true";
  return (
    <div className="login">
      <div className="card">
        <div className="brand">
          <div className="brand-mark">Z</div>
          ZeroDayHub
        </div>
        <h1>Sign in</h1>
        <p className="sub">Track vulnerabilities and get them fixed.</p>
        <LoginForm demo={showDemo ? DEMO : []} demoPassword="ZeroDay@2026" />
      </div>
    </div>
  );
}
