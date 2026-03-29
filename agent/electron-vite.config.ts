import { defineConfig } from "electron-vite";

export default defineConfig({
  main: {
    build: {
      outDir: "dist/main",
      rollupOptions: {
        external: ["electron", "electron-store", "systeminformation"],
      },
    },
  },
  preload: {
    build: {
      outDir: "dist/preload",
      rollupOptions: {
        external: ["electron"],
      },
    },
  },
  renderer: {
    build: {
      outDir: "dist/renderer",
    },
  },
});
