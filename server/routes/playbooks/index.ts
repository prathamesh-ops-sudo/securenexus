import type { Express } from "express";
import { registerPlaybooksCrudRoutes } from "./crud";
import { registerPlaybooksExecutionRoutes } from "./execution";
import { registerPlaybooksApprovalsRoutes } from "./approvals";
import { registerPlaybooksVersionsRoutes } from "./versions";
import { registerPlaybooksSchedulingRoutes } from "./scheduling";
import { registerPlaybooksSimulationsRoutes } from "./simulations";
import { registerPlaybooksNotificationsRoutes } from "./notifications";

export function registerPlaybooksRoutes(app: Express): void {
  registerPlaybooksCrudRoutes(app);
  registerPlaybooksExecutionRoutes(app);
  registerPlaybooksApprovalsRoutes(app);
  registerPlaybooksVersionsRoutes(app);
  registerPlaybooksSchedulingRoutes(app);
  registerPlaybooksSimulationsRoutes(app);
  registerPlaybooksNotificationsRoutes(app);
}
