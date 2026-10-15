import { FalkorDB, type Graph } from "falkordb";

export type Params = Record<string, unknown>;

let client: FalkorDB | undefined;
let graph: Graph | undefined;

export async function openGraph(): Promise<Graph> {
  if (graph) return graph;
  client = await FalkorDB.connect({ url: process.env.FALKORDB_URL ?? "redis://localhost:6379" });
  graph = client.selectGraph(process.env.FALKORDB_GRAPH ?? "clearance");
  return graph;
}

// The same FalkorDB server speaks plain Redis, which holds the Ask rate-limit counters.
export async function redis() {
  await openGraph();
  return client!.connection;
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
