import { write } from "../db.ts";

const INDEXES: [label: string, prop: string][] = [
  ["Repo", "name"],
  ["Module", "path"],
  ["ModuleVersion", "key"],
  ["Advisory", "id"],
  ["Package", "path"],
  ["Func", "key"],
  ["Team", "handle"],
  ["Verdict", "key"],
];

export async function ensureSchema(): Promise<void> {
  for (const [label, prop] of INDEXES) {
    try {
      await write(`CREATE INDEX FOR (n:${label}) ON (n.${prop})`);
    } catch (e) {
      if (!/already indexed|already exists/i.test((e as Error).message)) throw e;
    }
  }
}
