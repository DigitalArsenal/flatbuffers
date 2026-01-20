import { defineConfig } from 'vite';
import { resolve } from 'path';
import { viteSingleFile } from 'vite-plugin-singlefile';
import { readFileSync } from 'fs';

// Custom plugin to serve markdown files as rendered HTML
function markdownPlugin() {
  return {
    name: 'markdown-render',
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        if (req.url?.endsWith('.md')) {
          try {
            const filePath = resolve(__dirname, req.url.slice(1));
            const content = readFileSync(filePath, 'utf-8');

            // Dynamic import for marked (ESM)
            const { marked } = await import('marked');
            const html = marked(content);

            const fullHtml = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${req.url.split('/').pop()}</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/github-markdown-css/5.5.1/github-markdown-dark.min.css">
  <style>
    body {
      background: #0d1117;
      padding: 20px;
      max-width: 980px;
      margin: 0 auto;
    }
    .markdown-body {
      box-sizing: border-box;
      min-width: 200px;
      max-width: 980px;
      margin: 0 auto;
      padding: 45px;
    }
    @media (max-width: 767px) {
      .markdown-body { padding: 15px; }
    }
    .back-link {
      display: inline-block;
      margin-bottom: 20px;
      color: #58a6ff;
      text-decoration: none;
    }
    .back-link:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <a href="/" class="back-link">← Back to Demo</a>
  <article class="markdown-body">${html}</article>
</body>
</html>`;

            res.setHeader('Content-Type', 'text/html');
            res.end(fullHtml);
            return;
          } catch (e) {
            // File not found, continue to next middleware
          }
        }
        next();
      });
    },
  };
}

export default defineConfig({
  root: '.',
  base: './',
  plugins: [markdownPlugin(), viteSingleFile()],
  resolve: {
    alias: {
      // Allow importing from wasm/src
      '@flatbuffers': resolve(__dirname, '../../src'),
    },
  },
  optimizeDeps: {
    include: ['bip39', 'qrcode', 'buffer', 'vcard-cryptoperson'],
    exclude: ['@anthropic-ai/claude-code'],
  },
  build: {
    outDir: 'dist',
    // Required for vite-plugin-singlefile
    cssCodeSplit: false,
    assetsInlineLimit: 100000000, // Inline all assets
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
      },
      output: {
        inlineDynamicImports: true,
      },
    },
  },
  server: {
    port: 3000,
    open: true,
    // Allow serving files from parent directories
    fs: {
      allow: [
        // Allow wasm/src, dist, and build directories
        resolve(__dirname, '../..'),
        resolve(__dirname, '../../../../build/wasm/wasm'),
      ],
    },
  },
  // Copy WASM files to public directory for development
  publicDir: 'public',
  // Treat .fbs files as assets that can be imported as raw text
  assetsInclude: ['**/*.fbs'],
});
