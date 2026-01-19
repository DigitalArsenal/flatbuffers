import { defineConfig } from 'vite';
import { resolve } from 'path';
import { viteSingleFile } from 'vite-plugin-singlefile';

export default defineConfig({
  root: '.',
  base: './',
  plugins: [viteSingleFile()],
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
