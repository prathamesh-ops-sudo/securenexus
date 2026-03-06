import type { Express } from "express";
import { logger, p } from "./shared";
import { isAuthenticated } from "../auth";
import { getSecurityGraph, getAttackPathById, getAssetById, getAssetNeighbors } from "../security-graph-engine";

export function registerSecurityGraphRoutes(app: Express): void {
  app.get("/api/security-graph", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.query.orgId as string | undefined;
      const graph = getSecurityGraph(orgId);
      res.json(graph);
    } catch (error) {
      logger.child("routes").error("Security graph error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch security graph" });
    }
  });

  app.get("/api/security-graph/assets/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.query.orgId as string | undefined;
      const asset = getAssetById(p(req.params.id), orgId);
      if (!asset) return res.status(404).json({ message: "Asset not found" });
      res.json(asset);
    } catch (error) {
      logger.child("routes").error("Security graph asset error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch asset" });
    }
  });

  app.get("/api/security-graph/assets/:id/neighbors", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.query.orgId as string | undefined;
      const neighbors = getAssetNeighbors(p(req.params.id), orgId);
      res.json(neighbors);
    } catch (error) {
      logger.child("routes").error("Security graph neighbors error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch asset neighbors" });
    }
  });

  app.get("/api/security-graph/attack-paths", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.query.orgId as string | undefined;
      const graph = getSecurityGraph(orgId);
      res.json(graph.attackPaths);
    } catch (error) {
      logger.child("routes").error("Attack paths error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch attack paths" });
    }
  });

  app.get("/api/security-graph/attack-paths/:id", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.query.orgId as string | undefined;
      const path = getAttackPathById(p(req.params.id), orgId);
      if (!path) return res.status(404).json({ message: "Attack path not found" });
      res.json(path);
    } catch (error) {
      logger.child("routes").error("Attack path detail error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch attack path" });
    }
  });

  app.get("/api/security-graph/stats", isAuthenticated, async (req, res) => {
    try {
      const orgId = req.query.orgId as string | undefined;
      const graph = getSecurityGraph(orgId);
      res.json(graph.stats);
    } catch (error) {
      logger.child("routes").error("Security graph stats error", { error: String(error) });
      res.status(500).json({ message: "Failed to fetch security graph stats" });
    }
  });
}
