import express, { type Request, Response, NextFunction } from "express";
import { registerRoutes } from "./routes";
import { serveStatic } from "./static";
import { createServer } from "http";
import { startReportScheduler } from "./report-scheduler";
import { sliMiddleware, startSliCollection } from "./sli-middleware";
import { performanceBudgetMiddleware } from "./db-performance";
import { startJobWorker } from "./job-queue";
import { startSloAlerting } from "./slo-alerting";
import { replyInternal } from "./api-response";
import { envelopeMiddleware, autoDeprecationMiddleware } from "./envelope-middleware";
import { config } from "./config";
import { logger, correlationMiddleware, requestLogger } from "./logger";

const app = express();
const httpServer = createServer(app);

declare module "http" {
  interface IncomingMessage {
    rawBody: unknown;
  }
}

app.disable("x-powered-by");

app.use(
  express.json({
    limit: "1mb",
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  }),
);

app.use(express.urlencoded({ extended: false }));

app.use(sliMiddleware);
app.use(performanceBudgetMiddleware);

app.use(correlationMiddleware);
app.use(requestLogger);

// Standardised API response envelope – wraps every res.json() for /api/* paths
// into { data, meta, errors } and adds RFC 8594 deprecation headers to
// un-versioned legacy endpoints.
app.use(envelopeMiddleware);
app.use(autoDeprecationMiddleware);

export function log(message: string, source = "express") {
  logger.child(source).info(message);
}

(async () => {
  await registerRoutes(httpServer, app);

  const { seedDatabase } = await import("./seed");
  await seedDatabase();

  app.use((err: any, _req: Request, res: Response, next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    if (config.nodeEnv === "development" || config.nodeEnv === "test") {
      logger.child("express").error("Internal Server Error", { error: String(err), stack: err.stack });
    } else {
      logger.child("express").error(`Error ${status}: ${message}`);
    }

    if (res.headersSent) {
      return next(err);
    }

    return replyInternal(
      res,
      config.nodeEnv === "development" || config.nodeEnv === "test" ? message : "Internal Server Error",
    );
  });

  // importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (config.nodeEnv === "development" || config.nodeEnv === "test") {
    const { setupVite } = await import("./vite");
    await setupVite(httpServer, app);
  } else {
    serveStatic(app);
  }

  // ALWAYS serve the app on the port specified in the environment variable PORT
  // Other ports are firewalled. Default to 5000 if not specified.
  // this serves both the API and the client.
  // It is the only port that is not firewalled.
  const port = config.port;
  httpServer.listen(
    {
      port,
      host: "0.0.0.0",
      reusePort: true,
    },
    () => {
      logger.child("express").info(`serving on port ${port}`);
      startReportScheduler();
      startJobWorker();
      startSliCollection();
      startSloAlerting();
    },
  );
})();
