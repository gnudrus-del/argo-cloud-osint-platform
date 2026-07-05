"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import dynamic from "next/dynamic";
import type { GraphData } from "@/lib/types";

// react-force-graph usa il canvas/WebGL: va importato solo client-side.
const ForceGraph2D = dynamic(() => import("react-force-graph-2d"), { ssr: false });

const KIND_COLORS: Record<string, string> = {
  domain: "#f5b740",
  ip: "#6fcf97",
  email: "#e5645b",
  handle: "#9b8cff",
  person: "#ff9f6b",
  crypto: "#f2c94c",
  url: "#56ccf2",
};

const SEVERITY_RING: Record<string, string> = {
  critical: "#e5645b",
  high: "#ff9f6b",
  medium: "#f2c94c",
};

export default function GraphView({ data }: { data: GraphData }) {
  const ref = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ w: 800, h: 560 });

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const update = () => setSize({ w: el.clientWidth, h: Math.max(480, el.clientHeight) });
    update();
    const ro = new ResizeObserver(update);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // react-force-graph muta gli oggetti nodo: passiamo una copia difensiva.
  const graph = useMemo(
    () => ({
      nodes: (data.nodes || []).map((n) => ({ ...n })),
      links: (data.links || []).map((l) => ({ ...l })),
    }),
    [data]
  );

  return (
    <div ref={ref} style={{ width: "100%", height: 560, border: "1px solid var(--line)", borderRadius: 12, overflow: "hidden" }}>
      {/* @ts-expect-error dynamic import typing */}
      <ForceGraph2D
        width={size.w}
        height={size.h}
        graphData={graph}
        backgroundColor="#12100a"
        nodeRelSize={5}
        linkColor={() => "rgba(245,183,64,0.25)"}
        linkDirectionalParticles={1}
        linkDirectionalParticleWidth={1.5}
        nodeCanvasObject={(node: any, ctx: CanvasRenderingContext2D, scale: number) => {
          const r = 4 + Math.min(6, (node.degree || 0));
          const color = KIND_COLORS[node.kind] || "#c9b58a";
          ctx.beginPath();
          ctx.arc(node.x, node.y, r, 0, 2 * Math.PI);
          ctx.fillStyle = color;
          ctx.fill();
          const ring = SEVERITY_RING[node.severity];
          if (ring) {
            ctx.lineWidth = 2 / scale;
            ctx.strokeStyle = ring;
            ctx.stroke();
          }
          if (scale > 1.4) {
            ctx.font = `${11 / scale}px Inter, sans-serif`;
            ctx.fillStyle = "#f3e9d6";
            ctx.fillText(node.label || node.value, node.x + r + 2, node.y + 3);
          }
        }}
        nodeLabel={(node: any) =>
          `${node.kind}: ${node.value} (conf ${node.confidence?.toFixed?.(2) ?? "?"})`
        }
      />
    </div>
  );
}
