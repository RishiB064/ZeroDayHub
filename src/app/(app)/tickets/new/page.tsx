import { pageUser } from "@/lib/session";
import { listAssets } from "@/lib/services/assets";
import { listCves } from "@/lib/services/cves";
import { listAnalysts } from "@/lib/services/admin";
import NewTicketForm from "@/components/NewTicketForm";
import { PageHead } from "@/components/ui";

export default async function NewTicketPage() {
  const user = await pageUser("tickets:triage");
  const [assets, cves, analysts] = await Promise.all([listAssets(user), listCves(user), listAnalysts(user)]);
  return (
    <>
      <PageHead title="Triage a new ticket" sub="Link a CVE to an affected asset and assign an analyst." />
      <NewTicketForm
        assets={assets.map((a) => ({ id: Number(a.asset_id), label: `${a.hostname} (${a.environment})` }))}
        cves={cves.map((c) => ({ id: String(c.cve_id), label: `${c.cve_id} · ${c.severity} · ${c.title}` }))}
        analysts={analysts.map((a) => ({ id: Number(a.user_id), label: String(a.full_name) }))}
        defaultAnalyst={user.id}
      />
    </>
  );
}
