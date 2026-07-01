#!/usr/bin/env node
import { existsSync, readFileSync } from 'fs';
import { resolve } from 'path';

const root = resolve(process.cwd(), process.argv[2] ?? '.');
const html = readFileSync(resolve(root, 'index.html'), 'utf8');
const cssPath = resolve(root, 'styles.css');
const appPath = resolve(root, 'app.mjs');
const css = existsSync(cssPath) ? readFileSync(cssPath, 'utf8') : html;
const app = existsSync(appPath) ? readFileSync(appPath, 'utf8') : html;

const docsLinks = [...html.matchAll(/<a\b[^>]*class=(["'])[^"']*\bnav-link\b[^"']*\1[^>]*>\s*Docs\s*<\/a>/g)];
assert(docsLinks.length === 2, `expected 2 header Docs links, found ${docsLinks.length}`);

for (const [, , linkHtml] of docsLinks.map((match) => [match.index, match[0].length, match[0]])) {
  assert(attr(linkHtml, 'href') === '#docs', `header Docs href should be #docs: ${linkHtml}`);
  assert(attr(linkHtml, 'data-tab') === 'runtimes', `header Docs should activate runtimes: ${linkHtml}`);
  assert(attr(linkHtml, 'data-scroll-target') === 'docs', `header Docs should scroll to docs block: ${linkHtml}`);
  assert(!/\starget=/.test(linkHtml), `header Docs should not open a new page: ${linkHtml}`);
}

assert(/<div\b[^>]*\bid=(["'])docs\1[^>]*class=(["'])[^"']*\bglass-card\b[^"']*\2/.test(html) ||
  /<div\b[^>]*class=(["'])[^"']*\bglass-card\b[^"']*\1[^>]*\bid=(["'])docs\2/.test(html),
  'documentation card wrapper should have id="docs"');

const docsGridMatch = html.match(/<div class=(["'])docs-grid\1>([\s\S]*?)<\/div>\s*<\/div>\s*<\/section>/);
assert(docsGridMatch, 'expected docs-grid block');
const docCards = [...docsGridMatch[2].matchAll(/<a\b[^>]*class=(["'])[^"']*\bdoc-link-card\b[^"']*\1[^>]*>/g)].map((match) => match[0]);
assert(docCards.length === 5, `expected 5 documentation cards, found ${docCards.length}`);

const coreCard = docCards.find((card) => attr(card, 'href') === 'https://flatbuffers.dev');
assert(coreCard, 'expected a FlatBuffers core docs card linking to https://flatbuffers.dev');
assert(/\btarget=(["'])_blank\1/.test(coreCard), 'core docs card should open in a new tab');
assert(/\brel=(["'])noopener\1/.test(coreCard), 'core docs card should use rel="noopener"');
assert(/FlatBuffers Core Docs/.test(docsGridMatch[2]), 'core docs card should be labeled FlatBuffers Core Docs');

const docsGridCss = css.match(/\.docs-grid\s*\{([\s\S]*?)\}/);
assert(docsGridCss, 'expected .docs-grid CSS block');
assert(/justify-content\s*:\s*center\s*;/.test(docsGridCss[1]), '.docs-grid should center cards');
assert(/grid-template-columns\s*:\s*repeat\(\s*auto-fit\s*,\s*minmax\(200px,\s*240px\)\s*\)\s*;/.test(docsGridCss[1]),
  '.docs-grid should use centered fixed-width tracks');

assert(/dataset\.scrollTarget/.test(app), 'navigation handler should support data-scroll-target');

console.log('Landing docs navigation checks passed');

function attr(tag, name) {
  const match = tag.match(new RegExp(`\\b${name}=(["'])(.*?)\\1`, 'i'));
  return match?.[2] ?? '';
}

function assert(condition, message) {
  if (!condition) {
    console.error(message);
    process.exit(1);
  }
}
