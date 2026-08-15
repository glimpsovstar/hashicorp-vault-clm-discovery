import Link from "next/link";
import PageHeader from "@/components/page-header";
import ReportDownloadMenu from "@/components/report-download-menu";
import ReportExplorer from "@/components/report-explorer";
import { fetchReport, getScan, listScanCertificates, listIssuers, listScanFindings } from "@/lib/api";
import {
  buildFindings,
  coverageFromBlindSpot,
  resolveSeverityThresholds,
} from "@/lib/findings";

export const dynamic = "force-dynamic";

export default async function ScanReportPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const scan = await getScan(id);

  const backToScan = <Link href={`/scans/${id}`}>← Back to scan</Link>;

  if (scan.status !== "completed") {
    return (
      <>
        <PageHeader
          title="Environment report"
          subtitle="Scans"
          breadcrumbs={backToScan}
        />
        <section className="panel">
          <div className="panel-body">
            <p className="muted">
              Complete the scan to view its environment report.
            </p>
          </div>
        </section>
      </>
    );
  }

  const [report, certsResp, issuersResp, findingsResp] = await Promise.all([
    fetchReport(id),
    listScanCertificates(id),
    listIssuers(),
    listScanFindings(id).catch(() => ({ items: [] as Awaited<ReturnType<typeof listScanFindings>>["items"] })),
  ]);
  const certs = certsResp.items ?? [];
  const issuers = issuersResp.items ?? [];
  const persisted = findingsResp.items ?? [];

  // Prefer persisted M3 findings when present; fall back to on-read insights.
  // Shadow/issuer severity day cutoffs come from deploy env (#74).
  const findings = buildFindings(
    report,
    certs,
    issuers,
    persisted,
    resolveSeverityThresholds()
  );
  const coverage = coverageFromBlindSpot(report.blind_spot);

  // Defensive default: a version skew where the report omits recommendations
  // should render an empty section, not crash the page.
  const recommendations = report.recommendations ?? [];
  const generated = new Date(report.generated_at).toLocaleString();

  return (
    <>
      <PageHeader
        title="Environment report"
        subtitle="Scans"
        description={`Scan ${scan.id.slice(0, 8)}… · generated ${generated} · report v${report.report_version}`}
        breadcrumbs={backToScan}
        actions={<ReportDownloadMenu scanId={scan.id} />}
      />

      <ReportExplorer findings={findings} coverage={coverage} />

      {recommendations.length > 0 && (
        <section className="panel" style={{ marginTop: 24 }}>
          <div className="panel-header">
            <h2>Recommended actions</h2>
          </div>
          <div className="panel-body">
            <ul className="detail-list">
              {recommendations.map((rec) => (
                <li key={rec.code}>
                  <strong>{rec.phase}:</strong> {rec.title} ({rec.count})
                </li>
              ))}
            </ul>
          </div>
        </section>
      )}
    </>
  );
}
