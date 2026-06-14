"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

export default function DeleteButton({
  label,
  onDelete,
}: {
  label: string;
  onDelete: () => Promise<void>;
}) {
  const router = useRouter();
  const [loading, setLoading] = useState(false);

  async function handleClick() {
    if (!window.confirm(`Delete ${label}?`)) {
      return;
    }
    setLoading(true);
    try {
      await onDelete();
      router.refresh();
    } catch (err) {
      window.alert(err instanceof Error ? err.message : "Delete failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <button
      type="button"
      className="button button-secondary button-compact"
      onClick={handleClick}
      disabled={loading}
    >
      {loading ? "…" : "Delete"}
    </button>
  );
}
