import { join } from "node:path";

// Downloaded go.mod, CODEOWNERS and vulndb records, keyed by commit or advisory id so they never go
// stale. On Vercel only /tmp is writable.
export const CACHE_DIR =
  process.env.CLEARANCE_CACHE ?? (process.env.VERCEL ? "/tmp/clearance-cache" : join(import.meta.dirname, "../.cache"));
