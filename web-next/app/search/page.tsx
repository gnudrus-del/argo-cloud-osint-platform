"use client";

import { Suspense, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { api, ApiError } from "@/lib/api";
import AgentChips from "@/components/AgentChips";

const TARGET_TYPES = [
  { value: "auto", label: "Auto" },
  { value: "domain", label: "Dominio / Azienda" },
  { value: "email", label: "Email" },
  { value: "phone", label: "Telefono" },
  { value: "handle", label: "Username" },
  { value: "ip", label: "IP" },
  { value: "crypto", label: "Wallet crypto" },
];

function SearchInner() {
  const router = useRouter();
  const params = useSearchParams();
  const caseId = params.get("case") || "";

  const [target, setTarget] = useState("");
  const [type, setType] = useState("auto");
  const [plan, setPlan] = useState<{ agents: string[] } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const payload = () => ({
    command: target ? `Analizza ${target}` : "Ricerca OSINT",
    target,
    target_type: type,
    case_id: caseId,
    provider: "all",
    intensity: "meticulous",
  });

  async function preview() {
    setError(""); setBusy(true);
    try {
      const res = await api.plan(payload());
      setPlan(res.profile);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function launch() {
    setError(""); setBusy(true);
    try {
      const job = await api.createJob(payload());
      router.push(`/graph/${job.id}`);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <h1>Nuova ricerca</h1>
      <p className="muted">
        {caseId ? `Caso: ${caseId}` : "Nessun caso selezionato (per dati personali il caso è obbligatorio)."}
      </p>

      <div className="card" style={{ maxWidth: 640 }}>
        <label>Valore target</label>
        <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="example.com / user@mail / @handle" />
        <label>Tipo</label>
        <select value={type} onChange={(e) => setType(e.target.value)}>
          {TARGET_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
        </select>
        <div style={{ display: "flex", gap: 10, marginTop: 16 }}>
          <button className="btn" onClick={preview} disabled={busy || !target}>Anteprima piano</button>
          <button className="btn" onClick={launch} disabled={busy || !target}>🚀 Avvia ricerca</button>
        </div>
        {error && <p style={{ color: "var(--danger)", marginTop: 12 }}>{error}</p>}
      </div>

      {plan && (
        <div className="card" style={{ marginTop: 16, maxWidth: 640 }}>
          <h3>Piano automatico</h3>
          <p className="muted">Agenti che verranno eseguiti ({plan.agents?.length || 0}):</p>
          <AgentChips agents={plan.agents || []} />
        </div>
      )}
    </div>
  );
}

export default function SearchPage() {
  return (
    <Suspense fallback={<p className="muted">Caricamento…</p>}>
      <SearchInner />
    </Suspense>
  );
}
