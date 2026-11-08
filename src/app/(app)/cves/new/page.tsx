import { pageUser } from "@/lib/session";
import { listCwes } from "@/lib/services/cves";
import CveForm from "@/components/CveForm";
import { PageHead } from "@/components/ui";

export default async function NewCve() {
  const user = await pageUser("cves:write");
  const cwes = (await listCwes(user.role)).map((c) => ({ id: String(c.cwe_id), name: String(c.name) }));
  return (
    <>
      <PageHead title="Add a CVE" sub="Saved to MySQL first, then embedded and written to pgvector." />
      <CveForm cwes={cwes} editing={false} />
    </>
  );
}
