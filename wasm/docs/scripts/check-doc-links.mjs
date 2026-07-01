#!/usr/bin/env node
import { existsSync, readFileSync } from 'fs';
import { dirname, resolve } from 'path';

const htmlPath = resolve(process.cwd(), process.argv[2] ?? 'docs/index.html');
const siteRoot = resolve(process.cwd(), process.argv[3] ?? dirname(htmlPath));

if (!existsSync(htmlPath)) {
  console.error(`Landing page not found: ${htmlPath}`);
  process.exit(1);
}

const pageHtml = readFileSync(htmlPath, 'utf8');
const links = [...pageHtml.matchAll(/<a\b[^>]*\bhref=(["'])(.*?)\1/gi)]
  .map((match) => match[2])
  .filter((href) => isLocalDocumentLink(href));

const failures = [];

for (const href of links) {
  const [withoutHash, hash = ''] = href.split('#');
  const withoutQuery = withoutHash.split('?')[0];
  const targetPath = resolveTarget(htmlPath, siteRoot, withoutQuery);

  if (!existsSync(targetPath)) {
    failures.push(`${href} -> missing file ${targetPath}`);
    continue;
  }

  if (hash && !hasAnchor(targetPath, decodeURIComponent(hash))) {
    failures.push(`${href} -> missing anchor #${hash} in ${targetPath}`);
  }
}

if (failures.length) {
  console.error(`Found ${failures.length} broken local document link(s):`);
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log(`Checked ${links.length} local document link(s) from ${htmlPath}`);

function isLocalDocumentLink(href) {
  if (!href || href.startsWith('#')) return false;
  if (/^(?:https?:|mailto:|tel:|javascript:|data:)/i.test(href)) return false;

  const pathPart = href.split('#')[0].split('?')[0];
  return pathPart.endsWith('.html') || pathPart.endsWith('/');
}

function resolveTarget(sourcePath, rootPath, hrefPath) {
  if (!hrefPath) return sourcePath;

  const decodedPath = decodeURIComponent(hrefPath);
  if (decodedPath.startsWith('/')) {
    return resolve(rootPath, `.${decodedPath}`);
  }

  return resolve(dirname(sourcePath), decodedPath);
}

function hasAnchor(targetPath, anchor) {
  const html = readFileSync(targetPath, 'utf8');
  const escapedAnchor = escapeRegExp(anchor);
  return new RegExp(`\\b(?:id|name)=(["'])${escapedAnchor}\\1`, 'i').test(html);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
