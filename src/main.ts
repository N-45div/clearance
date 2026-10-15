// Local runner. On Vercel the web build in public/ is served by the CDN and src/app.ts by a function.
import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";
import { Hono } from "hono";
import app from "./app.ts";

const local = new Hono();
local.route("/", app);
local.use("/*", serveStatic({ root: "./public" }));

const port = Number(process.env.PORT ?? 8080);
serve({ fetch: local.fetch, port }, () => console.log(`Clearance on http://localhost:${port}`));
