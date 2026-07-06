"use client";

import { use, useEffect, useState } from "react";
import { api, ApiError, links } from "@/lib/api";
import type { GraphData, Job } from "@/lib/types";
import GraphView from "@/components/GraphView";
import AgentChips from "@/components/AgentChips";

// Next 15+ moved dynamic route params to a Promise (Async Request APIs).
// In a client component we unwrap with React.use().
export default function GraphPage({ params }: { params: Promise<{ jobId: string }> }) {
  const { jobId } = use(params);
  const [job, setJob] = useState<Job | null>(null);
  const [graph, setGraph] = useState<GraphData | null>(null);
  const [error, setError] = useState("");
  const [polling, setPolling] = useState(true);

  useEffect(() => {
    let timer: ReturnType<typeof setInterval> | undefined;
    async function tick() {
      try {
        const j = await api.job(jobId);
        setJob(j);
        if (j.status === "complete") {
          setPolling(false);
          if (timer) clearInterval(timer);
          try {
            setGraph(await api.graph(jobId));
          } catch {
            /* grafo non ancora disponibile */
          }
        } else if (j.status === "error") {
          setPolling(false);
          if (timer) clearInterval(timer);
        }
      } catch (e) {
        setError(e instanceof ApiError ? e.message : String(e));
        setPolling(false);
        if (timer) clearInterval(timer);
      }
    }
    tick();
    timer = setInterval(tick, 2500);
    return () => { if (timer) clearInterval(timer); };
  }, [jobId]);

  return (
    <div>
      <h1>Job {jobId.slice(0, 8)}</h1>
      {job && (
        <p className="muted">
          Target: <strong>{job.target || "—"}</strong> · tipo {job.target_type || "—"} ·{" "}
          <span className={`badge status-${job.status}`}>{job.status}</span>
          {polling && " · aggiornamento in corso…"}
        </p>
      )}
      {error && <div className="card" style={{ borderColor: "var(--danger)" }}>Errore: {error}</div>}

      {job?.agents && (
        <div className="card">
          <h3>Agenti</h3>
          <AgentChips agents={job.agents} />
        </div>
      )}

      <h2>Grafo entità-relazioni</h2>
      {graph ? (
        <>
          <GraphView data={graph} />
          <p className="muted" style={{ marginTop: 8 }}>
            {graph.nodes.length} nodi · {graph.links.length} relazioni
          </p>
        </>
      ) : (
        <div className="card"><p className="muted">
          {job?.status === "complete" ? "Grafo non disponibile per questo job." : "In attesa del completamento del job…"}
        </p></div>
      )}

      {job?.status === "complete" && (
        <div className="card smallLinks" style={{ marginTop: 16 }}>
          <h3>Export</h3>
          <a href={links.reportPdf(jobId)} target="_blank">PDF</a>
          <a href={links.reportJson(jobId)} target="_blank">JSON</a>
          <a href={links.forensicMd(jobId)} target="_blank">Forensic</a>
          <a href={links.stix(jobId)} target="_blank">STIX 2.1</a>
          <a href={links.misp(jobId)} target="_blank">MISP</a>
        </div>
      )}
    </div>
  );
}
