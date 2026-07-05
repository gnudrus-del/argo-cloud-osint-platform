"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import type { CaseRecord } from "@/lib/types";

export default function CasesPage() {
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const data = await api.cases();
        setCases(data.cases || []);
      } catch (e) {
        setError(e instanceof ApiError ? e.message : String(e));
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  return (
    <div>
      <h1>Casi</h1>
      <p className="muted">Ogni ricerca appartiene a un caso con base giuridica e scope autorizzato.</p>

      {error && <div className="card" style={{ borderColor: "var(--danger)" }}>Errore: {error}</div>}
      {loading && <p className="muted">Caricamento…</p>}

      <div className="grid cols-2" style={{ marginTop: 16 }}>
        {cases.map((c) => (
          <div className="card" key={c.id}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h3>{c.title}</h3>
              <span className={`badge status-${c.status === "open" ? "complete" : ""}`}>{c.status}</span>
            </div>
            <p className="muted">{c.purpose || "Nessuno scopo dichiarato."}</p>
            <p style={{ fontSize: 12 }} className="muted">
              Target autorizzati: {c.allowed_targets?.length || 0} · agg. {c.updated_at?.slice(0, 10)}
            </p>
            <Link href={`/search?case=${c.id}`} className="btn" style={{ marginTop: 8 }}>
              Nuova ricerca nel caso
            </Link>
          </div>
        ))}
        {!loading && cases.length === 0 && !error && (
          <p className="muted">Nessun caso ancora. Creane uno dal backend o dalla ricerca.</p>
        )}
      </div>
    </div>
  );
}
