import { defineConfig } from 'vite';
import preact from '@preact/preset-vite';

export default defineConfig({
  plugins: [preact()],
  build: {
    outDir: '../spiffs',
    emptyOutDir: true,
    assetsInlineLimit: 100000,
    rollupOptions: {
      output: {
        manualChunks: undefined,
        inlineDynamicImports: true,
        entryFileNames: 'app.js',
        assetFileNames: '[name][extname]',
      },
    },
  },
  server: {
    proxy: {
      '/api': 'http://192.168.4.1',
      '/ws': { target: 'ws://192.168.4.1', ws: true },
    },
  },
});
