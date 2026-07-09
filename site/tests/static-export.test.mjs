import assert from "node:assert/strict";
import { access, readFile, readdir } from "node:fs/promises";
import test from "node:test";

test("exports a script-free GitHub Pages artifact with relative assets", async () => {
  const html = await readFile(new URL("../pages/index.html", import.meta.url), "utf8");

  assert.match(html, /<title>ReproAssert — The test before the fix<\/title>/);
  assert.match(html, /rel="canonical" href="https:\/\/atomics-hub\.github\.io\/reproassert\/"/);
  assert.doesNotMatch(html, /<script\b/i);
  assert.doesNotMatch(html, /rel="modulepreload"/i);
  assert.doesNotMatch(html, /(?:href|src)="\/assets\//i);
  assert.match(html, /href="\.\/assets\//);
  assert.match(html, /href="\.\/icon\.svg"/);
  await access(new URL("../pages/assets", import.meta.url));
  const assetFiles = await readdir(new URL("../pages/assets", import.meta.url), {
    recursive: true,
  });
  assert.equal(assetFiles.some((file) => file.endsWith(".js")), false);
  await access(new URL("../pages/404.html", import.meta.url));
  await access(new URL("../pages/.nojekyll", import.meta.url));
  const schema = JSON.parse(
    await readFile(new URL("../pages/reproassert-report.schema.json", import.meta.url), "utf8"),
  );
  assert.equal(
    schema.$id,
    "https://atomics-hub.github.io/reproassert/reproassert-report.schema.json",
  );
});
