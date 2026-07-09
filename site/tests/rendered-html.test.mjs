import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function render() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request("http://localhost/", {
      headers: { accept: "text/html" },
    }),
    {
      ASSETS: {
        fetch: async () => new Response("Not found", { status: 404 }),
      },
    },
    {
      waitUntil() {},
      passThroughOnException() {},
    },
  );
}

test("server-renders the ReproAssert proof surface", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>ReproAssert — The test before the fix<\/title>/i);
  assert.match(html, /The test/);
  assert.match(html, /before the/);
  assert.match(html, /repeatable_base_failure/);
  assert.match(html, /Twenty frozen cases\. Zero scored results\./);
  assert.match(html, /Contract preview · placeholder paths · not benchmark evidence/);
  assert.match(html, /candidate\.patch/);
  assert.match(html, /reproassert-report\.json/);
  assert.match(html, /aria-label="Primary navigation"/);
  assert.doesNotMatch(html, /codex-preview|react-loading-skeleton|Starter Project/);
});

test("keeps public claims and business math bounded in source", async () => {
  const [page, layout, packageJson] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);

  assert.match(page, /Current maximum claim/);
  assert.match(page, /not benchmark evidence/);
  assert.match(page, /Zero willingness-to-pay/);
  assert.match(page, /51/);
  assert.match(page, /\$199/);
  assert.match(page, /\$10,149/);
  assert.match(page, /No\s+semantic-validity claim yet/);
  assert.match(page, /No native host execution/);
  assert.doesNotMatch(page, /testimonial|customer logo|state of the art/i);
  assert.match(layout, /title: "ReproAssert — The test before the fix"/);
  assert.doesNotMatch(layout, /codex-preview|_sites-preview|Starter Project/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);
});
