import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { isDashboardRole } from "../routes/dashboard-role";

describe("dashboard role route matching", () => {
  it("lets exact sibling routes handle non-role dashboard paths", async () => {
    const app = express();
    app.get("/api/dashboard/:role", (req, res, next) => {
      if (!isDashboardRole(req.params.role)) {
        next("route");
        return;
      }
      res.json({ route: "role" });
    });
    app.get("/api/dashboard/role", (_req, res) => {
      res.json({ route: "exact" });
    });

    await request(app).get("/api/dashboard/role").expect(200, { route: "exact" });
  });

  it("accepts only supported dashboard role values", () => {
    expect(isDashboardRole("ciso")).toBe(true);
    expect(isDashboardRole("soc_manager")).toBe(true);
    expect(isDashboardRole("analyst")).toBe(true);
    expect(isDashboardRole("role")).toBe(false);
    expect(isDashboardRole("stunning-stats")).toBe(false);
  });
});
