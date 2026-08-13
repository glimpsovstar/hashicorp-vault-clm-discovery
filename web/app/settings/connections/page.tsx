import PageHeader from "@/components/page-header";
import ConnectionsForm from "./connections-form";

export const dynamic = "force-dynamic";

export default function ConnectionsPage() {
  return (
    <>
      <PageHeader
        title="Connections"
        subtitle="Settings"
        description="Configure Vault, AAP Controller, and the EDA webhook. Secrets are stored on the server and never shown after save. Environment variables remain valid for Compose."
      />
      <ConnectionsForm />
    </>
  );
}
