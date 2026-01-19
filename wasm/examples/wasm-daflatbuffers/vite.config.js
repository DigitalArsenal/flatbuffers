import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  root: '.',
  base: './',
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
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
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
