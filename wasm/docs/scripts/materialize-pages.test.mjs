import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { materializePages } from "./materialize-pages.mjs";

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "flatbuffers-pages-materialize-"));
  const source = join(root, "dist");
  const destination = join(root, "docs");
  await mkdir(join(source, "assets"), { recursive: true });
  await mkdir(join(destination, "source"), { recursive: true });
  await writeFile(join(source, "index.html"), "reviewed landing\n");
  await writeFile(join(source, "wallet-callback.html"), "reviewed callback\n");
  await writeFile(join(source, "assets/app.js"), "reviewed app\n");
  await writeFile(join(destination, "index.html"), "stale protected landing\n");
  await writeFile(join(destination, "retired-loader.js"), "stale mutable loader\n");
  await writeFile(join(destination, "source/guide.md"), "preserved source\n");
  return { destination, source };
}

test("materializer replaces the complete landing tree and preserves explicit documentation inputs", async () => {
  const { destination, source } = await fixture();
  await materializePages({ source, destination });
  assert.equal(await readFile(join(destination, "index.html"), "utf8"), "reviewed landing\n");
  assert.equal(await readFile(join(destination, "wallet-callback.html"), "utf8"), "reviewed callback\n");
  assert.equal(await readFile(join(destination, "assets/app.js"), "utf8"), "reviewed app\n");
  assert.equal(await readFile(join(destination, "source/guide.md"), "utf8"), "preserved source\n");
  await assert.rejects(readFile(join(destination, "retired-loader.js")), /ENOENT/u);
  await materializePages({ source, destination, check: true });
});

test("materializer check rejects byte drift and unexpected public root entries", async () => {
  const drifted = await fixture();
  await materializePages(drifted);
  await writeFile(join(drifted.destination, "index.html"), "drifted\n");
  await assert.rejects(materializePages({ ...drifted, check: true }), /differs: index\.html/u);

  const unexpected = await fixture();
  await materializePages(unexpected);
  await writeFile(join(unexpected.destination, "unreviewed.js"), "unreviewed\n");
  await assert.rejects(materializePages({ ...unexpected, check: true }), /unexpected public Pages output/u);
});
