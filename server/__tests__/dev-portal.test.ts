import express, { type Express } from "express";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { mockDbExecute, mockDbTransaction, mockCreateAuditLog } = vi.hoisted(() => ({
  mockDbExecute: vi.fn(),
  mockDbTransaction: vi.fn(),
  mockCreateAuditLog: vi.fn(),
}));

vi.mock("../auth", () => ({
  isAuthenticated: (req: express.Request, _res: express.Response, next: express.NextFunction) => {
    req.user = { id: "super-admin-1", email: "super-admin@example.com", isSuperAdmin: true } as Express.User;
    next();
  },
}));

vi.mock("../middleware/super-admin", () => ({
  requireSuperAdmin: (_req: express.Request, _res: express.Response, next: express.NextFunction) => next(),
}));

vi.mock("../db", () => ({
  db: {
    execute: mockDbExecute,
    transaction: mockDbTransaction,
  },
  getPoolHealth: vi.fn(),
  checkPoolConnectivity: vi.fn(),
}));

vi.mock("../storage/audit", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../storage/audit")>();
  return { ...actual, createAuditLog: mockCreateAuditLog };
});

vi.mock("../logger", () => ({
  logger: {
    child: () => ({
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    }),
  },
}));

vi.mock("../config", () => ({
  config: {
    port: 5513,
    nodeEnv: "test",
    databaseUrl: "postgres://test",
    aws: { region: "us-east-1" },
    ai: { backend: "test", modelId: "test" },
  },
}));

vi.mock("../openapi", () => ({
  buildOpenApiSpec: vi.fn().mockReturnValue({ paths: {} }),
}));

import { registerDevPortalRoutes } from "../routes/dev-portal";

function createApp(): Express {
  const app = express();
  app.use(express.json());
  registerDevPortalRoutes(app);
  return app;
}

function mockTableQuery(rows: unknown[] = []) {
  mockDbExecute.mockResolvedValueOnce({ rows: [{ "?column?": 1 }] }).mockResolvedValueOnce({
    rows: [{ column_name: "id" }, { column_name: "email" }, { column_name: "password_hash" }],
  });
  const txExecute = vi.fn().mockResolvedValueOnce({ rows: [] }).mockResolvedValueOnce({ rows });
  mockDbTransaction.mockImplementationOnce(async (callback: (tx: { execute: typeof txExecute }) => Promise<unknown>) =>
    callback({ execute: txExecute }),
  );
}

describe("developer portal database query", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("redacts sensitive columns and audits the read", async () => {
    mockTableQuery([{ id: "user-1", email: "user@example.com", password_hash: "hash-value" }]);

    const response = await request(createApp())
      .post("/api/dev-portal/db/query")
      .send({ table: "users", where: [], limit: 10 });

    expect(response.status).toBe(200);
    expect(response.body.data.rows[0]).toEqual({
      id: "user-1",
      email: "user@example.com",
      password_hash: "[REDACTED]",
    });
    expect(mockCreateAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: "super-admin-1",
        resourceType: "dev_portal_database",
        resourceId: "users",
        details: expect.objectContaining({
          filterColumns: [],
          rowCount: 1,
        }),
      }),
    );
  });

  it("rejects filtering and ordering by sensitive columns", async () => {
    mockDbExecute
      .mockResolvedValueOnce({ rows: [{ "?column?": 1 }] })
      .mockResolvedValueOnce({ rows: [{ column_name: "id" }, { column_name: "password_hash" }] });

    const filterResponse = await request(createApp())
      .post("/api/dev-portal/db/query")
      .send({ table: "users", where: [{ column: "password_hash", op: "like", value: "a%" }] });

    expect(filterResponse.status).toBe(400);
    expect(filterResponse.body.errors[0].code).toBe("SENSITIVE_COLUMN");

    vi.clearAllMocks();
    mockDbExecute
      .mockResolvedValueOnce({ rows: [{ "?column?": 1 }] })
      .mockResolvedValueOnce({ rows: [{ column_name: "id" }, { column_name: "password_hash" }] });

    const orderResponse = await request(createApp())
      .post("/api/dev-portal/db/query")
      .send({ table: "users", orderBy: "password_hash" });

    expect(orderResponse.status).toBe(400);
    expect(orderResponse.body.errors[0].code).toBe("SENSITIVE_COLUMN");
  });

  it("refuses unsupported tables and operators", async () => {
    mockDbExecute.mockResolvedValueOnce({ rows: [] });
    const tableResponse = await request(createApp()).post("/api/dev-portal/db/query").send({ table: "does_not_exist" });
    expect(tableResponse.status).toBe(404);

    vi.clearAllMocks();
    mockDbExecute
      .mockResolvedValueOnce({ rows: [{ "?column?": 1 }] })
      .mockResolvedValueOnce({ rows: [{ column_name: "id" }] });
    const operatorResponse = await request(createApp())
      .post("/api/dev-portal/db/query")
      .send({ table: "users", where: [{ column: "id", op: "regexp", value: ".*" }] });
    expect(operatorResponse.status).toBe(400);
    expect(operatorResponse.body.errors[0].code).toBe("INVALID_FILTER");
  });
});
