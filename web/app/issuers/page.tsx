import PageHeader from "@/components/page-header";
import IssuersTable from "@/components/issuers-table";
import { listIssuers } from "@/lib/api";

export default async function IssuersPage() {
  const { items: rawItems } = await listIssuers();
  const items = rawItems ?? [];

  return (
    <>
      <PageHeader
        title="Issuers"
        description="Certificate authorities and issuing entities discovered during scans."
      />

      <section className="panel">
        <div className="panel-body panel-body-flush data-table-wrap">
          <IssuersTable items={items} />
        </div>
      </section>
    </>
  );
}
