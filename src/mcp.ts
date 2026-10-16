// The fleet graph as an MCP server (Streamable HTTP, stateless, JSON responses). It serves the same
// read-only tools the triage agent uses, so Claude Code, Cursor or any MCP client can ask the graph
// directly. Nothing here can write: every tool is a fixed GRAPH.RO_QUERY or run_cypher's capped one.
import { TOOLS } from "./agent.ts";

export const PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26"];

type Rpc = { jsonrpc: "2.0"; id?: string | number | null; method?: string; params?: Record<string, unknown> };
type Reply = { jsonrpc: "2.0"; id: string | number | null; result?: unknown; error?: { code: number; message: string } };

const ok = (id: Rpc["id"], result: unknown): Reply => ({ jsonrpc: "2.0", id: id ?? null, result });
const fail = (id: Rpc["id"], code: number, message: string): Reply => ({ jsonrpc: "2.0", id: id ?? null, error: { code, message } });

const INSTRUCTIONS =
  "Clearance: Go vulnerability verdicts for 20 Grafana services, decided from govulncheck call paths stored in FalkorDB. " +
  "Start with fleet_summary or blast_radius(advisory). 'under_investigation' means the reachability scan failed; never treat it as safe.";

// Returns undefined for notifications, which get an empty 202.
export async function handle(msg: Rpc): Promise<Reply | undefined> {
  if (msg?.jsonrpc !== "2.0" || typeof msg.method !== "string") return fail(msg?.id, -32600, "invalid request");
  const isNotification = msg.id === undefined;
  switch (msg.method) {
    case "initialize": {
      const asked = String(msg.params?.protocolVersion ?? "");
      return ok(msg.id, {
        protocolVersion: PROTOCOL_VERSIONS.includes(asked) ? asked : PROTOCOL_VERSIONS[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "clearance", title: "Clearance fleet graph", version: "1.0.0" },
        instructions: INSTRUCTIONS,
      });
    }
    case "ping":
      return ok(msg.id, {});
    case "tools/list":
      return ok(msg.id, {
        tools: Object.entries(TOOLS).map(([name, t]) => ({
          name, description: t.description, inputSchema: t.parameters, annotations: { readOnlyHint: true, openWorldHint: false },
        })),
      });
    case "tools/call": {
      const name = String(msg.params?.name ?? "");
      const tool = TOOLS[name];
      if (!tool) return fail(msg.id, -32602, `unknown tool ${name}`);
      try {
        const result = await tool.run((msg.params?.arguments ?? {}) as Record<string, string>);
        const text = JSON.stringify(result ?? null);
        return ok(msg.id, { content: [{ type: "text", text: text.slice(0, 60_000) }], isError: false });
      } catch (e) {
        return ok(msg.id, { content: [{ type: "text", text: (e as Error).message }], isError: true });
      }
    }
    default:
      if (isNotification) return undefined;
      return fail(msg.id, -32601, `method not found: ${msg.method}`);
  }
}
