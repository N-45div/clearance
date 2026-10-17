import { readFileSync } from "node:fs";
import { join } from "node:path";
import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import { marked } from "marked";

const escapeHtml = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

// blog.html is static: the article is rendered from src/blog.md (front matter + Markdown) at build time,
// so the page needs no script to read, and link previews see the real title and description.
function blogPage(): Plugin {
  const source = join(import.meta.dirname, "src/blog.md");
  return {
    name: "clearance-blog",
    transformIndexHtml: {
      order: "pre",
      handler(html, ctx) {
        if (!ctx.filename.endsWith("blog.html")) return html;
        const text = readFileSync(source, "utf8").replace(/\r\n/g, "\n");
        const fm = /^---\n([\s\S]*?)\n---\n/.exec(text);
        const meta: Record<string, string> = {};
        for (const line of fm?.[1].split("\n") ?? []) {
          const m = /^(\w+):\s*(.*)$/.exec(line);
          if (m) meta[m[1]] = m[2].replace(/^"(.*)"$/, "$1").replace(/\\"/g, '"');
        }
        const body = fm ? text.slice(fm[0].length) : text;
        const minutes = Math.max(1, Math.round(body.split(/\s+/).length / 230));
        return html
          .replaceAll("%TITLE%", escapeHtml(meta.title ?? "Clearance"))
          .replaceAll("%DESCRIPTION%", escapeHtml(meta.description ?? ""))
          .replace("%MINUTES%", String(minutes))
          .replace("<!--ARTICLE-->", marked.parse(body, { async: false }));
      },
    },
  };
}

export default defineConfig({
  root: import.meta.dirname,
  plugins: [react(), blogPage()],
  server: { proxy: { "/api": "http://localhost:8080" } },
  build: {
    outDir: "../public",
    emptyOutDir: true,
    rollupOptions: { input: { main: join(import.meta.dirname, "index.html"), blog: join(import.meta.dirname, "blog.html") } },
  },
});
