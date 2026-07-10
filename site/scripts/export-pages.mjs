import { cp, mkdir, readdir, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = resolve(import.meta.dirname, "..");
const output = resolve(root, "pages");
const workerUrl = pathToFileURL(resolve(root, "dist/server/index.js"));
workerUrl.searchParams.set("static-export", `${process.pid}-${Date.now()}`);
const { default: worker } = await import(workerUrl.href);

const response = await worker.fetch(
  new Request("http://localhost/", { headers: { accept: "text/html" } }),
  { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } },
  { waitUntil() {}, passThroughOnException() {} },
);
if (!response.ok) {
  throw new Error(`static page render failed with HTTP ${response.status}`);
}

let html = await response.text();
html = html
  .replace(/<script\b[^>]*>[\s\S]*?<\/script>\s*/gi, "")
  .replace(/<link\b(?=[^>]*\brel=["']modulepreload["'])[^>]*>\s*/gi, "")
  .replaceAll("/assets/", "./assets/")
  .replace(
    /href="(?:https:\/\/atomics-hub\.github\.io)?\/icon\.svg[^"]*"/g,
    'href="./icon.svg"',
  );
if (/<script\b/i.test(html) || /(?:href|src)="\/assets\//i.test(html)) {
  throw new Error("static export retained executable scripts or root-relative assets");
}

await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
await copyStaticAssets(
  resolve(root, "dist/client/assets"),
  resolve(output, "assets"),
);
await cp(resolve(root, "app/icon.svg"), resolve(output, "icon.svg"));
await cp(
  resolve(root, "../schemas/reproassert-report.schema.json"),
  resolve(output, "reproassert-report.schema.json"),
);
for (const name of [
  "benchmark-v02-replay-bundle.schema.json",
  "benchmark-v02-replay-result.schema.json",
]) {
  await cp(resolve(root, "../schemas", name), resolve(output, name));
}
await writeFile(resolve(output, "index.html"), html);
await writeFile(resolve(output, "404.html"), html);
await writeFile(resolve(output, ".nojekyll"), "");

async function copyStaticAssets(source, destination) {
  await mkdir(destination, { recursive: true });
  for (const entry of await readdir(source, { withFileTypes: true })) {
    const sourcePath = resolve(source, entry.name);
    const destinationPath = resolve(destination, entry.name);
    if (entry.isDirectory()) {
      await copyStaticAssets(sourcePath, destinationPath);
    } else if (/\.(?:css|woff2)$/.test(entry.name)) {
      await cp(sourcePath, destinationPath);
    }
  }
}
