"use client";

import DeleteButton from "@/components/delete-button";
import { deleteIssuer, statusBadgeClass, type Issuer } from "@/lib/api";

export default function IssuersTable({ items }: { items: Issuer[] }) {
  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Subject CN</th>
          <th>Status</th>
          <th>Days left</th>
          <th>Issuer DN</th>
          <th>CA</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {items.map((issuer) => (
          <tr key={issuer.id}>
            <td>{issuer.subject_cn || issuer.fingerprint_sha256.slice(0, 12)}</td>
            <td>
              <span className={statusBadgeClass(issuer.status)}>{issuer.status}</span>
            </td>
            <td>{issuer.days_until_expiry}</td>
            <td>{issuer.issuer_dn}</td>
            <td>{issuer.is_ca ? "Yes" : "No"}</td>
            <td>
              <DeleteButton
                label={issuer.subject_cn || issuer.fingerprint_sha256.slice(0, 12)}
                onDelete={() => deleteIssuer(issuer.id)}
              />
            </td>
          </tr>
        ))}
        {items.length === 0 && (
          <tr>
            <td colSpan={6} className="muted">
              No issuers discovered yet.
            </td>
          </tr>
        )}
      </tbody>
    </table>
  );
}
