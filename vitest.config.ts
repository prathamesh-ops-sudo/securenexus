import { defineConfig } from "vitest/config";
import path from "path";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["server/__tests__/**/*.test.ts", "shared/__tests__/**/*.test.ts"],
    exclude: ["node_modules", "dist", "build"],
    testTimeout: 15_000,
    hookTimeout: 10_000,
    coverage: {
      provider: "v8",
      include: ["server/**/*.ts", "shared/**/*.ts"],
      exclude: [
        "server/__tests__/**",
        "server/vite.ts",
        "server/static.ts",
        "shared/__tests__/**",
        "**/*.d.ts",
      ],
      thresholds: {
        statements: 10,
        branches: 10,
        functions: 10,
        lines: 10,
      },
    },
    setupFiles: [],
    pool: "forks",
  },
  resolve: {
    alias: {
      "@shared": path.resolve(__dirname, "shared"),
      "@": path.resolve(__dirname, "client/src"),
    },
  },
});
