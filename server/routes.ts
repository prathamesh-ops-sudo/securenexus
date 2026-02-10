import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { setupAuth, registerAuthRoutes, isAuthenticated } from "./replit_integrations/auth";
import { insertAlertSchema, insertIncidentSchema, insertCommentSchema, insertTagSchema } from "@shared/schema";

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  await setupAuth(app);
  registerAuthRoutes(app);

  // Dashboard
  app.get("/api/dashboard/stats", isAuthenticated, async (req, res) => {
    try {
      const stats = await storage.getDashboardStats();
      res.json(stats);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch stats" });
    }
  });

  // Alerts
  app.get("/api/alerts", isAuthenticated, async (req, res) => {
    try {
      const { search } = req.query;
      if (search && typeof search === "string") {
        const results = await storage.searchAlerts(search);
        return res.json(results);
      }
      const allAlerts = await storage.getAlerts();
      res.json(allAlerts);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch alerts" });
    }
  });

  app.get("/api/alerts/:id", isAuthenticated, async (req, res) => {
    try {
      const alert = await storage.getAlert(req.params.id);
      if (!alert) return res.status(404).json({ message: "Alert not found" });
      res.json(alert);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch alert" });
    }
  });

  app.post("/api/alerts", isAuthenticated, async (req, res) => {
    try {
      const parsed = insertAlertSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid alert data", errors: parsed.error.flatten() });
      }
      const alert = await storage.createAlert(parsed.data);
      res.status(201).json(alert);
    } catch (error) {
      console.error("Error creating alert:", error);
      res.status(500).json({ message: "Failed to create alert" });
    }
  });

  app.patch("/api/alerts/:id", isAuthenticated, async (req, res) => {
    try {
      const parsed = insertAlertSchema.partial().safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid update data", errors: parsed.error.flatten() });
      }
      const alert = await storage.updateAlert(req.params.id, parsed.data);
      if (!alert) return res.status(404).json({ message: "Alert not found" });
      res.json(alert);
    } catch (error) {
      res.status(500).json({ message: "Failed to update alert" });
    }
  });

  app.patch("/api/alerts/:id/status", isAuthenticated, async (req, res) => {
    try {
      const { status, incidentId } = req.body;
      if (!status) return res.status(400).json({ message: "Status required" });
      const alert = await storage.updateAlertStatus(req.params.id, status, incidentId);
      if (!alert) return res.status(404).json({ message: "Alert not found" });
      res.json(alert);
    } catch (error) {
      res.status(500).json({ message: "Failed to update alert status" });
    }
  });

  // Alert tags
  app.get("/api/alerts/:id/tags", isAuthenticated, async (req, res) => {
    try {
      const alertTags = await storage.getAlertTags(req.params.id);
      res.json(alertTags);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch alert tags" });
    }
  });

  app.post("/api/alerts/:id/tags", isAuthenticated, async (req, res) => {
    try {
      const { tagId } = req.body;
      if (!tagId) return res.status(400).json({ message: "tagId required" });
      await storage.addAlertTag(req.params.id, tagId);
      res.status(201).json({ message: "Tag added" });
    } catch (error) {
      res.status(500).json({ message: "Failed to add tag" });
    }
  });

  app.delete("/api/alerts/:alertId/tags/:tagId", isAuthenticated, async (req, res) => {
    try {
      await storage.removeAlertTag(req.params.alertId, req.params.tagId);
      res.json({ message: "Tag removed" });
    } catch (error) {
      res.status(500).json({ message: "Failed to remove tag" });
    }
  });

  // Incidents
  app.get("/api/incidents", isAuthenticated, async (req, res) => {
    try {
      const allIncidents = await storage.getIncidents();
      res.json(allIncidents);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch incidents" });
    }
  });

  app.get("/api/incidents/:id", isAuthenticated, async (req, res) => {
    try {
      const incident = await storage.getIncident(req.params.id);
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      res.json(incident);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch incident" });
    }
  });

  app.get("/api/incidents/:id/alerts", isAuthenticated, async (req, res) => {
    try {
      const incidentAlerts = await storage.getAlertsByIncident(req.params.id);
      res.json(incidentAlerts);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch incident alerts" });
    }
  });

  app.post("/api/incidents", isAuthenticated, async (req, res) => {
    try {
      const parsed = insertIncidentSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid incident data", errors: parsed.error.flatten() });
      }
      const incident = await storage.createIncident(parsed.data);
      res.status(201).json(incident);
    } catch (error) {
      console.error("Error creating incident:", error);
      res.status(500).json({ message: "Failed to create incident" });
    }
  });

  app.patch("/api/incidents/:id", isAuthenticated, async (req, res) => {
    try {
      const parsed = insertIncidentSchema.partial().safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid update data", errors: parsed.error.flatten() });
      }
      const incident = await storage.updateIncident(req.params.id, parsed.data);
      if (!incident) return res.status(404).json({ message: "Incident not found" });
      res.json(incident);
    } catch (error) {
      res.status(500).json({ message: "Failed to update incident" });
    }
  });

  // Incident comments
  app.get("/api/incidents/:id/comments", isAuthenticated, async (req, res) => {
    try {
      const comments = await storage.getComments(req.params.id);
      res.json(comments);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch comments" });
    }
  });

  app.post("/api/incidents/:id/comments", isAuthenticated, async (req, res) => {
    try {
      const parsed = insertCommentSchema.safeParse({
        ...req.body,
        incidentId: req.params.id,
      });
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid comment data", errors: parsed.error.flatten() });
      }
      const comment = await storage.createComment(parsed.data);
      res.status(201).json(comment);
    } catch (error) {
      res.status(500).json({ message: "Failed to create comment" });
    }
  });

  app.delete("/api/comments/:id", isAuthenticated, async (req, res) => {
    try {
      const deleted = await storage.deleteComment(req.params.id);
      if (!deleted) return res.status(404).json({ message: "Comment not found" });
      res.json({ message: "Comment deleted" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete comment" });
    }
  });

  // Incident tags
  app.get("/api/incidents/:id/tags", isAuthenticated, async (req, res) => {
    try {
      const incTags = await storage.getIncidentTags(req.params.id);
      res.json(incTags);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch incident tags" });
    }
  });

  app.post("/api/incidents/:id/tags", isAuthenticated, async (req, res) => {
    try {
      const { tagId } = req.body;
      if (!tagId) return res.status(400).json({ message: "tagId required" });
      await storage.addIncidentTag(req.params.id, tagId);
      res.status(201).json({ message: "Tag added" });
    } catch (error) {
      res.status(500).json({ message: "Failed to add tag" });
    }
  });

  app.delete("/api/incidents/:incidentId/tags/:tagId", isAuthenticated, async (req, res) => {
    try {
      await storage.removeIncidentTag(req.params.incidentId, req.params.tagId);
      res.json({ message: "Tag removed" });
    } catch (error) {
      res.status(500).json({ message: "Failed to remove tag" });
    }
  });

  // Tags
  app.get("/api/tags", isAuthenticated, async (req, res) => {
    try {
      const allTags = await storage.getTags();
      res.json(allTags);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch tags" });
    }
  });

  app.post("/api/tags", isAuthenticated, async (req, res) => {
    try {
      const parsed = insertTagSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ message: "Invalid tag data", errors: parsed.error.flatten() });
      }
      const tag = await storage.createTag(parsed.data);
      res.status(201).json(tag);
    } catch (error) {
      res.status(500).json({ message: "Failed to create tag" });
    }
  });

  // Audit logs
  app.get("/api/audit-logs", isAuthenticated, async (req, res) => {
    try {
      const logs = await storage.getAuditLogs();
      res.json(logs);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch audit logs" });
    }
  });

  return httpServer;
}
