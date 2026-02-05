#!/usr/bin/env node
/**
 * Converts markdown files in docs/ to styled HTML in docs-html/
 * Uses the same styling as the vite dev server markdown plugin
 */

import { readFileSync, writeFileSync, readdirSync, mkdirSync, existsSync } from 'fs';
import { join, basename } from 'path';
import { marked } from 'marked';

// Configure marked to generate heading IDs (GitHub-style slugs)
const renderer = new marked.Renderer();
renderer.heading = function ({ text, depth }) {
  const slug = text.toLowerCase()
    .replace(/<[^>]*>/g, '')       // strip HTML tags
    .replace(/[^\w\s-]/g, '')      // remove non-word chars
    .replace(/\s+/g, '-')          // spaces to hyphens
    .replace(/-+/g, '-')           // collapse multiple hyphens
    .trim();
  return `<h${depth} id="${slug}">${text}</h${depth}>\n`;
};
marked.use({ renderer });

const DOCS_DIR = join(import.meta.dirname, '..', 'docs');
const OUTPUT_DIR = join(import.meta.dirname, '..', 'docs-html');

// HTML template with premium dark theme styling
function wrapHtml(title, content) {
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title} - DA FlatBuffers</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/github-markdown-css/5.5.1/github-markdown-dark.min.css">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-primary: #000000;
      --bg-secondary: rgba(42, 42, 45, 0.72);
      --bg-tertiary: rgba(66, 66, 69, 0.72);
      --accent-primary: #3b82f6;
      --accent-secondary: #60a5fa;
      --text-primary: #F5F5F7;
      --text-secondary: rgba(255, 255, 255, 0.6);
      --border-color: rgba(59, 130, 246, 0.3);
      --glow-color: rgba(59, 130, 246, 0.15);
    }

    * {
      box-sizing: border-box;
    }

    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      margin: 0;
      padding: 0;
      min-height: 100vh;
      position: relative;
      overflow-x: hidden;
    }

    /* Animated background */
    body::before {
      content: '';
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background:
        radial-gradient(ellipse at 20% 20%, rgba(59, 130, 246, 0.06) 0%, transparent 50%),
        radial-gradient(ellipse at 80% 80%, rgba(59, 130, 246, 0.04) 0%, transparent 50%),
        radial-gradient(ellipse at 50% 50%, rgba(59, 130, 246, 0.03) 0%, transparent 70%);
      pointer-events: none;
      z-index: 0;
    }

    /* Grid pattern overlay */
    body::after {
      content: '';
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background-image:
        linear-gradient(rgba(59, 130, 246, 0.02) 1px, transparent 1px),
        linear-gradient(90deg, rgba(59, 130, 246, 0.02) 1px, transparent 1px);
      background-size: 50px 50px;
      pointer-events: none;
      z-index: 0;
    }

    .page-container {
      position: relative;
      z-index: 1;
      max-width: 900px;
      margin: 0 auto;
      padding: 40px 20px;
    }

    .back-link {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 10px 20px;
      margin-bottom: 30px;
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      color: var(--accent-secondary);
      text-decoration: none;
      font-weight: 500;
      font-size: 14px;
      transition: all 0.2s ease;
    }

    .back-link:hover {
      background: var(--bg-tertiary);
      border-color: var(--accent-primary);
      transform: translateY(-1px);
    }

    .markdown-body {
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      padding: 48px;
    }

    .markdown-body h1,
    .markdown-body h2,
    .markdown-body h3,
    .markdown-body h4 {
      color: var(--text-primary);
      border-bottom-color: var(--border-color);
      font-weight: 600;
    }

    .markdown-body h1 {
      background: linear-gradient(135deg, var(--accent-secondary), var(--accent-primary));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      font-size: 2.2em;
      margin-bottom: 24px;
    }

    .markdown-body a {
      color: var(--accent-secondary);
    }

    .markdown-body a:hover {
      color: var(--accent-primary);
    }

    .markdown-body code {
      background: var(--bg-tertiary);
      border: 1px solid var(--border-color);
      border-radius: 4px;
      padding: 2px 6px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.9em;
    }

    .markdown-body pre {
      background: var(--bg-primary) !important;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 16px;
      overflow-x: auto;
    }

    .markdown-body pre code {
      background: transparent;
      border: none;
      padding: 0;
      font-size: 0.85em;
      line-height: 1.6;
    }

    .markdown-body table {
      border-collapse: collapse;
      width: 100%;
      margin: 20px 0;
    }

    .markdown-body table th,
    .markdown-body table td {
      border: 1px solid var(--border-color);
      padding: 12px 16px;
      text-align: left;
    }

    .markdown-body table th {
      background: var(--bg-tertiary);
      font-weight: 600;
      color: var(--accent-secondary);
    }

    .markdown-body table tr:nth-child(even) {
      background: rgba(59, 130, 246, 0.03);
    }

    .markdown-body blockquote {
      border-left: 4px solid var(--accent-primary);
      background: var(--bg-tertiary);
      padding: 16px 20px;
      margin: 20px 0;
      border-radius: 0 8px 8px 0;
    }

    .markdown-body hr {
      border: none;
      height: 1px;
      background: var(--border-color);
      margin: 32px 0;
    }

    .markdown-body ul, .markdown-body ol {
      padding-left: 24px;
    }

    .markdown-body li {
      margin: 8px 0;
    }

    @media (max-width: 768px) {
      .page-container {
        padding: 20px 16px;
      }
      .markdown-body {
        padding: 24px;
        border-radius: 12px;
      }
      .markdown-body h1 {
        font-size: 1.8em;
      }
    }
  </style>
</head>
<body>
  <div class="page-container">
    <a href="https://digitalarsenal.github.io/flatbuffers/" class="back-link">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M19 12H5M12 19l-7-7 7-7"/>
      </svg>
      Back to DA FlatBuffers
    </a>
    <article class="markdown-body">${content}</article>
  </div>
</body>
</html>`;
}

// Create output directory
if (!existsSync(OUTPUT_DIR)) {
  mkdirSync(OUTPUT_DIR, { recursive: true });
}

// Process all markdown files
const files = readdirSync(DOCS_DIR).filter(f => f.endsWith('.md'));

console.log(`Converting ${files.length} markdown files to HTML...`);

for (const file of files) {
  const inputPath = join(DOCS_DIR, file);
  const outputFile = file.replace('.md', '.html');
  const outputPath = join(OUTPUT_DIR, outputFile);

  const markdown = readFileSync(inputPath, 'utf-8');

  // Convert .md links to .html links
  const processedMarkdown = markdown.replace(/\]\(([^)]+)\.md\)/g, ']($1.html)');

  const html = marked(processedMarkdown);
  const title = file.replace('.md', '').replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
  const fullHtml = wrapHtml(title, html);

  writeFileSync(outputPath, fullHtml);
  console.log(`  ${file} -> ${outputFile}`);
}

console.log('Done!');
