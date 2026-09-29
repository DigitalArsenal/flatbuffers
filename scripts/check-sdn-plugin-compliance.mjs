#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDirectory, "..");
const toolPath = path.resolve(
  repoRoot,
  "../sdn-flow/tools/run-plugin-compliance-check.mjs",
);

const result = spawnSync(
  process.execPath,
  [toolPath, "--repo-root", repoRoot, ...process.argv.slice(2)],
  { stdio: "inherit" },
);

process.exit(result.status ?? 1);
