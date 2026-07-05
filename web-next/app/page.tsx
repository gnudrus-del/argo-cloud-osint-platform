"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import type { Capabilities, Job } from "@/lib/types";

export default function Dashboard() {
  const [caps, setCaps] = useState<Capabilities | null>(null);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [error, setError] = useState<string>("");

  useEffect(() => {
    (async () => {
      try {
        const [c, j] = await Promise.all([api.capabilities(), api.jobs()]);
        setCaps(c);
        setJobs(j.jobs || []);
      } catch (e) {
        setError(e instanceof ApiError ? e.message : String(e));
      }
    })();
  }, []);

  const toolsOk = caps?.tools?.filter((t) => t.available).length ?? 0;
  const toolsTot = caps?.tools?.length ?? 0;
  const providersOk = caps?.search_providers?.filter((p) => p.configured).length ?? 0;
  const aiOn = caps ? Object.values(caps.ai_enrichment || {}).filter(Boolean).length : 0;

  return (
    <div>
      <h1>Dashboard</h1>
      <p className="muted">Panoramica operativa della piattaforma Argo.</p>

      {error && (
        <div className="card" style={{ borderColor: "var(--danger)" }}>
          <strong>Errore:</strong> {error}
          {error.toLowerCase().includes("accesso") && (
            <p className="muted">Autenticati sul backend legacy, poi ricarica.</p>
          )}
        </div>
      )}

      <div className="grid cols-3" style={{ marginTop: 16 }}>
        <div className="card">
          <h3>Agenti</h3>
          <div style={{ fontSize: 30, color: "var(--accent)" }}>{caps?.agents?.length ?? "—"}</div>
          <p className="muted">{caps?.always_on_agents?.length ?? 0} sempre attivi · {caps?.gated_agents?.length ?? 0} gated</p>
        </div>
        <div className="card">
          <h3>Tool</h3>
          <div style={{ fontSize: 30, color: "var(--accent)" }}>{toolsOk}<span className="muted" style={{ fontSize: 18 }}>/{toolsTot}</span></div>
          <p className="muted">disponibili</p>
        </div>
        <div className="card">
          <h3>Provider</h3>
          <div style={{ fontSize: 30, color: "var(--accent)" }}>{providersOk}</div>
          <p className="muted">API configurate</p>
        </div>
        <div className="card">
          <h3>AI locale</h3>
          <div style={{ fontSize: 30, color: "var(--accent)" }}>{aiOn}</div>
          <p className="muted">enrichment attivi (OCR/NER/…)</p>
        </div>
        <div className="card">
          <h3>Coda</h3>
          <div style={{ fontSize: 30, color: "var(--accent)" }}>{caps?.queue?.pending ?? 0}</div>
          <p className="muted">job in attesa</p>
        </div>
      </div>

      <h2>Ultimi job</h2>
      <div className="card">
        {jobs.length === 0 && <p className="muted">Nessun job. Avvia una ricerca dalla tab Ricerca.</p>}
        {jobs.slice(0, 8).map((j) => (
          <div className="tableRow" key={j.id}>
            <div>
              <Link href={`/graph/${j.id}`}>{j.target || j.id.slice(0, 8)}</Link>
              <span className="muted" style={{ marginLeft: 8 }}>{j.target_type || "—"}</span>
            </div>
            <span className={`badge status-${j.status}`}>{j.status}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
