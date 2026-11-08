import { pageUser } from "@/lib/session";
import SearchPanel from "@/components/SearchPanel";
import { PageHead } from "@/components/ui";

export default async function SearchPage() {
  await pageUser("search");
  return (
    <>
      <PageHead title="Search" sub="Describe a problem in your own words and find related advisories." />
      <SearchPanel />
    </>
  );
}
