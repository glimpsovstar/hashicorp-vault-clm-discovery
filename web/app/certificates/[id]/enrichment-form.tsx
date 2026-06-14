"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import type { Certificate } from "@/lib/api";
import { patchCertificate } from "@/lib/api";

export default function EnrichmentForm({ cert }: { cert: Certificate }) {
  const router = useRouter();
  const [owner, setOwner] = useState(cert.owner || "");
  const [team, setTeam] = useState(cert.team || "");
  const [environment, setEnvironment] = useState(cert.environment || "");
  const [tags, setTags] = useState((cert.tags || []).join(", "));
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setMessage("");
    try {
      await patchCertificate(cert.id, {
        owner: owner || undefined,
        team: team || undefined,
        environment: environment || undefined,
        tags: tags ? tags.split(",").map((t) => t.trim()).filter(Boolean) : [],
      });
      setMessage("Saved");
      router.refresh();
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  return (
    <form onSubmit={onSubmit}>
      <h3 style={{ marginTop: 0 }}>Governance</h3>
      <div className="form-row">
        <div className="form-field">
          <label htmlFor="owner">Owner</label>
          <input id="owner" value={owner} onChange={(e) => setOwner(e.target.value)} />
        </div>
        <div className="form-field">
          <label htmlFor="team">Team</label>
          <input id="team" value={team} onChange={(e) => setTeam(e.target.value)} />
        </div>
        <div className="form-field">
          <label htmlFor="environment">Environment</label>
          <input
            id="environment"
            value={environment}
            onChange={(e) => setEnvironment(e.target.value)}
          />
        </div>
      </div>
      <div className="form-field" style={{ marginBottom: 12 }}>
        <label htmlFor="tags">Tags (comma-separated)</label>
        <input id="tags" value={tags} onChange={(e) => setTags(e.target.value)} />
      </div>
      <button type="submit" className="button button-primary" disabled={saving}>
        {saving ? "Saving..." : "Save"}
      </button>
      {message && <p className="help-text">{message}</p>}
    </form>
  );
}
