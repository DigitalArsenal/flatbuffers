#!/usr/bin/env node

import { cp, mkdir, readFile, readdir, rm, stat } from "node:fs/promises";
import { createHash } from "node:crypto";
import { posix, resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const PRESERVED_PAGES_INPUTS = Object.freeze([
  "CNAME",
  "docs-html",
  "mkdocs.yml",
  "overrides",
  "site",
  "source",
  "wasm-runtimes",
]);

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function treeFiles(root, directory = root, prefix = "") {
  const files = new Map();
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const relative = prefix ? posix.join(prefix, entry.name) : entry.name;
    const path = resolve(directory, entry.name);
    if (entry.isSymbolicLink()) throw new Error(`Pages tree contains a symlink: ${relative}`);
    if (entry.isDirectory()) {
      for (const [name, digest] of await treeFiles(root, path, relative)) files.set(name, digest);
    } else if (entry.isFile()) {
      files.set(relative, sha256(await readFile(path)));
    } else {
      throw new Error(`Pages tree contains an unsupported entry: ${relative}`);
    }
  }
  return files;
}

async function directoryNames(path) {
  try {
    const details = await stat(path);
    if (!details.isDirectory()) throw new Error(`Pages path is not a directory: ${path}`);
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
  return (await readdir(path, { withFileTypes: true })).map((entry) => {
    if (entry.isSymbolicLink()) throw new Error(`Pages root contains a symlink: ${entry.name}`);
    return entry.name;
  });
}

async function verifyMaterialization(source, destination) {
  const sourceFiles = await treeFiles(source);
  const destinationFiles = await treeFiles(destination);
  for (const [path, digest] of sourceFiles) {
    if (destinationFiles.get(path) !== digest) throw new Error(`materialized Pages output differs: ${path}`);
  }
  const sourceTopLevel = new Set((await directoryNames(source)));
  const allowedTopLevel = new Set([...sourceTopLevel, ...PRESERVED_PAGES_INPUTS]);
  for (const name of await directoryNames(destination)) {
    if (!allowedTopLevel.has(name)) throw new Error(`unexpected public Pages output: ${name}`);
  }
  for (const required of ["index.html", "wallet-callback.html"]) {
    if (!sourceFiles.has(required)) throw new Error(`reviewed Pages source is missing: ${required}`);
  }
}

export async function materializePages({ source, destination, check = false }) {
  const sourceRoot = resolve(source);
  const destinationRoot = resolve(destination);
  await stat(sourceRoot).then((details) => {
    if (!details.isDirectory()) throw new Error(`reviewed Pages source is not a directory: ${sourceRoot}`);
  });
  if (!check) {
    await mkdir(destinationRoot, { recursive: true });
    const preserved = new Set(PRESERVED_PAGES_INPUTS);
    for (const name of await directoryNames(destinationRoot)) {
      if (!preserved.has(name)) await rm(resolve(destinationRoot, name), { recursive: true, force: true });
    }
    for (const name of await directoryNames(sourceRoot)) {
      await cp(resolve(sourceRoot, name), resolve(destinationRoot, name), {
        recursive: true,
        force: true,
        errorOnExist: false,
      });
    }
  }
  await verifyMaterialization(sourceRoot, destinationRoot);
}

function parseArguments(argv) {
  const options = { check: false };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--check") {
      if (options.check) throw new Error("duplicate argument: --check");
      options.check = true;
      continue;
    }
    if (!["--source", "--destination"].includes(argument)) throw new Error(`unknown argument: ${argument}`);
    const key = argument.slice(2);
    if (options[key]) throw new Error(`duplicate argument: ${argument}`);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`missing value: ${argument}`);
    options[key] = value;
    index += 1;
  }
  if (!options.source || !options.destination) throw new Error("--source and --destination are required");
  return options;
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  materializePages(parseArguments(process.argv.slice(2))).catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
