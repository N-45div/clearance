import { FalkorDB, type Graph } from "falkordb";

export type Params = Record<string, unknown>;

let client: FalkorDB | undefined;
let graph: Graph | undefined;

export async function openGraph(): Promise<Graph> {
  if (graph) return graph;
  const c = await FalkorDB.connect({ url: process.env.FALKORDB_URL ?? "redis://localhost:6379" });
  // A dropped connection must fail the request in flight, not crash the process; the next call reconnects.
  c.on("error", (e: Error) => {
    console.error(`falkordb: ${e.message}`);
    if (client === c) {
      client = undefined;
      graph = undefined;
    }
  });
  client = c;
  graph = c.selectGraph(process.env.FALKORDB_GRAPH ?? "clearance");
  return graph;
}

// A second graph on the same server for the Ask rate-limit counters, kept apart from the fleet graph
// that the agent can query. (FalkorDB Cloud's user may run graph commands but not plain Redis ones.)
export async function writeLimits<T = Record<string, unknown>>(cypher: string, params: Params = {}): Promise<T[]> {
  await openGraph();
  const reply = await client!.selectGraph(`${process.env.FALKORDB_GRAPH ?? "clearance"}_limits`)
    .query<T>(cypher, { params: params as never, TIMEOUT: 5_000 });
  return reply.data ?? [];
}

export async function closeGraph(): Promise<void> {
  await client?.close();
  client = undefined;
  graph = undefined;
}

// Writes go through here (ingest only). Bulk loads need more than the 1 s default timeout.
export async function write<T = Record<string, unknown>>(cypher: string, params: Params = {}): Promise<T[]> {
  const g = await openGraph();
  const reply = await g.query<T>(cypher, { params: params as never, TIMEOUT: 60_000 });
  return reply.data ?? [];
}

// Everything the agent and the API run goes through GRAPH.RO_QUERY, so no tool can change the graph.
export async function read<T = Record<string, unknown>>(cypher: string, params: Params = {}, timeoutMs = 10_000): Promise<T[]> {
  const g = await openGraph();
  const reply = await g.roQuery<T>(cypher, { params: params as never, TIMEOUT: timeoutMs });
  return reply.data ?? [];
}
