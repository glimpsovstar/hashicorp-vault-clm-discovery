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
      <h3>Governance</h3>
      <div className="form-row">
        <label>
          Owner
          <input value={owner} onChange={(e) => setOwner(e.target.value)} />
        </label>
        <label>
          Team
          <input value={team} onChange={(e) => setTeam(e.target.value)} />
        </label>
        <label>
          Environment
          <input value={environment} onChange={(e) => setEnvironment(e.target.value)} />
        </label>
      </div>
      <label style={{ display: "block", marginBottom: 12 }}>
        Tags (comma-separated)
        <input value={tags} onChange={(e) => setTags(e.target.value)} style={{ width: "100%" }} />
      </label>
      <button type="submit" disabled={saving}>{saving ? "Saving..." : "Save"}</button>
      {message && <p className="muted">{message}</p>}
    </form>
  );
}
