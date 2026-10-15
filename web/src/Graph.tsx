import { useEffect, useRef } from "react";
import "@falkordb/canvas";
import type FalkorDBCanvas from "@falkordb/canvas";
import type { Data, GraphNode } from "@falkordb/canvas";
import type { GraphData } from "./api";

const RADIUS: Record<string, number> = { Advisory: 9, Repo: 7, ModuleVersion: 5, Team: 6 };

// Short labels so the picture reads at a glance; the full key is on the node's data.
function label(node: GraphNode): string {
  const name = String(node.data.name ?? "");
  if (node.labels.includes("ModuleVersion")) {
    const at = name.lastIndexOf("@");
    const path = name.slice(0, at);
    return `${path === "stdlib" ? "go" : path.split("/").slice(-2).join("/")} ${name.slice(at + 1)}`;
  }
  if (node.labels.includes("Team")) return name.replace(/^@grafana\//, "@");
  return name;
}

// The advisory's neighbourhood straight from FalkorDB: Advisory <- module version <- repo -> team.
export function Graph({ data, onRepo }: { data: GraphData | undefined; onRepo: (repo: string) => void }) {
  const ref = useRef<FalkorDBCanvas>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas || !data) return;
    const css = getComputedStyle(document.documentElement);
    const ink = css.getPropertyValue("--ink").trim();
    const muted = css.getPropertyValue("--muted").trim();
    const panel = css.getPropertyValue("--panel").trim();
    canvas.setConfig({
      backgroundColor: css.getPropertyValue("--canvas-bg").trim(),
      foregroundColor: ink,
      layoutOptions: { force: { linkDistance: 26, collisionPadding: 34 } },
      node: {
        nodeCanvasObject: (node, ctx) => {
          const r = RADIUS[node.labels[0] ?? ""] ?? 4;
          const x = node.x ?? 0;
          const y = node.y ?? 0;
          ctx.beginPath();
          ctx.arc(x, y, r, 0, 2 * Math.PI);
          ctx.fillStyle = node.color;
          ctx.fill();
          ctx.lineWidth = 1;
          ctx.strokeStyle = panel;
          ctx.stroke();
          const repo = node.labels.includes("Repo") || node.labels.includes("Advisory");
          ctx.font = `${repo ? 600 : 500} ${repo ? 13 : 10.5}px Inter, sans-serif`;
          ctx.fillStyle = repo ? ink : muted;
          ctx.textAlign = "left";
          ctx.textBaseline = "middle";
          ctx.fillText(label(node), x + r + 3, y);
        },
        nodePointerAreaPaint: (node, color, ctx) => {
          const r = (RADIUS[node.labels[0] ?? ""] ?? 4) + 2;
          ctx.beginPath();
          ctx.arc(node.x ?? 0, node.y ?? 0, r, 0, 2 * Math.PI);
          ctx.fillStyle = color;
          ctx.fill();
        },
      },
      eventHandlers: {
        onNodeClick: (node: GraphNode) => {
          if (node.labels.includes("Repo") && node.data.name) onRepo(String(node.data.name));
        },
      },
    });
    canvas.setData(data as unknown as Data);
    // Fit once the force layout has mostly settled.
    const timers = [900, 2200].map((ms) => setTimeout(() => canvas.zoomToFit(1), ms));
    return () => timers.forEach(clearTimeout);
  }, [data, onRepo]);

  return (
    <div className="canvas-wrap">
      <falkordb-canvas ref={ref} />
      <div className="canvas-key">
        <span><i className="dot" style={{ background: "var(--violet)" }} />advisory</span>
        <span><i className="dot" style={{ background: "#8B8D98" }} />module version</span>
        <span><i className="dot" style={{ background: "var(--affected)" }} />affected</span>
        <span><i className="dot" style={{ background: "var(--safe)" }} />not affected</span>
        <span><i className="dot" style={{ background: "var(--unknown)" }} />under investigation</span>
        <span><i className="dot" style={{ background: "var(--accent)" }} />team</span>
      </div>
    </div>
  );
}
