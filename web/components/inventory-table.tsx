"use client";

import Link from "next/link";
import DeleteButton from "@/components/delete-button";
import { deleteCertificate, statusBadgeClass, type Certificate } from "@/lib/api";

export default function InventoryTable({ items }: { items: Certificate[] }) {
  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Subject CN</th>
          <th>Status</th>
          <th>Days left</th>
          <th>Chain</th>
          <th>Observations</th>
          <th>Last seen</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {items.map((cert) => (
          <tr key={cert.id}>
            <td>
              <Link href={`/certificates/${cert.id}`}>
                {cert.subject_cn || cert.fingerprint_sha256.slice(0, 12)}
              </Link>
              {!cert.hostname_matches_san && (
                <span className="muted" title="Hostname mismatch">
                  {" "}
                  ⚠
                </span>
              )}
            </td>
            <td>
              <span className={statusBadgeClass(cert.status)}>{cert.status}</span>
            </td>
            <td>{cert.days_until_expiry}</td>
            <td>{cert.chain_status}</td>
            <td>{cert.observation_count ?? 0}</td>
            <td>{new Date(cert.last_seen).toLocaleString()}</td>
            <td>
              <DeleteButton
                label={cert.subject_cn || cert.fingerprint_sha256.slice(0, 12)}
                onDelete={() => deleteCertificate(cert.id)}
              />
            </td>
          </tr>
        ))}
        {items.length === 0 && (
          <tr>
            <td colSpan={7} className="muted">
              No certificates discovered yet. Run a scan from the Scans page.
            </td>
          </tr>
        )}
      </tbody>
    </table>
  );
}
