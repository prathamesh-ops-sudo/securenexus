import type { Request, Response, NextFunction, ErrorRequestHandler } from 'express';
import { logger } from '../logger';

const log = logger.child('error-handler');

/**
 * Enterprise-Grade Error Handling System
 * 
 * Features:
 * - Standardized error responses
 * - Error categorization
 * - Logging and monitoring
 * - User-friendly messages
 * - Stack traces in development only
 * - Error tracking integration (Sentry-ready)
 */

export class AppError extends Error {
  constructor(
    public statusCode: number,
    public message: string,
    public code?: string,
    public details?: any
  ) {
    super(message);
    this.name = 'AppError';
    Error.captureStackTrace(this, this.constructor);
  }
}

// Common error types
export class ValidationError extends AppError {
  constructor(message: string, details?: any) {
    super(400, message, 'VALIDATION_ERROR', details);
    this.name = 'ValidationError';
  }
}

export class AuthenticationError extends AppError {
  constructor(message: string = 'Authentication required') {
    super(401, message, 'AUTHENTICATION_ERROR');
    this.name = 'AuthenticationError';
  }
}

export class AuthorizationError extends AppError {
  constructor(message: string = 'Insufficient permissions') {
    super(403, message, 'AUTHORIZATION_ERROR');
    this.name = 'AuthorizationError';
  }
}

export class NotFoundError extends AppError {
  constructor(resource: string = 'Resource') {
    super(404, `${resource} not found`, 'NOT_FOUND');
    this.name = 'NotFoundError';
  }
}

export class ConflictError extends AppError {
  constructor(message: string) {
    super(409, message, 'CONFLICT');
    this.name = 'ConflictError';
  }
}

export class PlanLimitError extends AppError {
  constructor(limit: string, current: number, max: number) {
    super(
      402,
      `Plan limit exceeded for ${limit}`,
      'PLAN_LIMIT_EXCEEDED',
      { limit, current, max }
    );
    this.name = 'PlanLimitError';
  }
}

export class RateLimitError extends AppError {
  constructor(retryAfter: number) {
    super(
      429,
      'Rate limit exceeded',
      'RATE_LIMIT_EXCEEDED',
      { retryAfter }
    );
    this.name = 'RateLimitError';
  }
}

export class ExternalServiceError extends AppError {
  constructor(service: string, message: string) {
    super(502, `${service} error: ${message}`, 'EXTERNAL_SERVICE_ERROR');
    this.name = 'ExternalServiceError';
  }
}

/**
 * Error logging with categorization
 */
function logError(error: Error, req: Request): void {
  const errorInfo = {
    name: error.name,
    message: error.message,
    stack: error.stack,
    method: req.method,
    url: req.url,
    body: req.body,
    query: req.query,
    params: req.params,
    user: (req as any).user?.id,
    orgId: (req as any).orgId,
    ip: req.ip,
    userAgent: req.get('user-agent'),
  };

  if (error instanceof AppError) {
    if (error.statusCode >= 500) {
      log.error('Server error', errorInfo);
    } else if (error.statusCode >= 400) {
      log.warn('Client error', errorInfo);
    }
  } else {
    log.error('Unexpected error', errorInfo);
  }

  // TODO: Send to error tracking service (Sentry)
  // if (process.env.SENTRY_DSN) {
  //   Sentry.captureException(error, {
  //     contexts: {
  //       request: errorInfo,
  //     },
  //   });
  // }
}

/**
 * Format error response
 */
function formatErrorResponse(error: Error, isDevelopment: boolean): any {
  if (error instanceof AppError) {
    const response: any = {
      error: error.message,
      code: error.code,
    };

    if (error.details) {
      response.details = error.details;
    }

    if (isDevelopment && error.stack) {
      response.stack = error.stack;
    }

    return response;
  }

  // Generic error
  const response: any = {
    error: isDevelopment
      ? error.message
      : 'An unexpected error occurred. Please try again.',
    code: 'INTERNAL_SERVER_ERROR',
  };

  if (isDevelopment && error.stack) {
    response.stack = error.stack;
  }

  return response;
}

/**
 * Global error handler middleware (must be last)
 */
export const errorHandler: ErrorRequestHandler = (
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  // Log error
  logError(error, req);

  // Determine status code
  let statusCode = 500;
  if (error instanceof AppError) {
    statusCode = error.statusCode;
  }

  // Special handling for specific error types
  if (error.name === 'ValidationError' || error.name === 'ZodError') {
    statusCode = 400;
  } else if (error.name === 'UnauthorizedError') {
    statusCode = 401;
  } else if (error.name === 'ForbiddenError') {
    statusCode = 403;
  }

  // Don't send response if headers already sent
  if (res.headersSent) {
    return next(error);
  }

  // Format and send response
  const isDevelopment = process.env.NODE_ENV === 'development';
  const response = formatErrorResponse(error, isDevelopment);

  res.status(statusCode).json(response);
};

/**
 * 404 handler (must be before error handler)
 */
export function notFoundHandler(req: Request, res: Response, next: NextFunction): void {
  const error = new NotFoundError('Endpoint');
  next(error);
}

/**
 * Async error wrapper (eliminates try-catch in route handlers)
 * 
 * Usage:
 * app.get('/api/data', asyncHandler(async (req, res) => {
 *   const data = await someAsyncOperation();
 *   res.json(data);
 * }));
 */
export function asyncHandler(
  fn: (req: Request, res: Response, next: NextFunction) => Promise<any>
) {
  return (req: Request, res: Response, next: NextFunction): void => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

/**
 * Validation error formatter (for Zod errors)
 */
export function formatZodError(error: any): ValidationError {
  const details = error.errors?.map((err: any) => ({
    field: err.path.join('.'),
    message: err.message,
  }));

  return new ValidationError('Validation failed', details);
}

/**
 * Graceful shutdown handler
 */
export function setupGracefulShutdown(server: any): void {
  const shutdown = (signal: string) => {
    log.info(`${signal} received, starting graceful shutdown`);

    server.close(() => {
      log.info('HTTP server closed');
      
      // Close database connections, etc.
      // TODO: Add cleanup logic
      
      process.exit(0);
    });

    // Force shutdown after 30 seconds
    setTimeout(() => {
      log.error('Forcefully shutting down after timeout');
      process.exit(1);
    }, 30000);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

/**
 * Unhandled rejection handler
 */
export function setupUnhandledRejectionHandler(): void {
  process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
    log.error('Unhandled Promise Rejection', {
      reason: reason?.message || reason,
      stack: reason?.stack,
    });

    // TODO: Send to error tracking
    // if (process.env.SENTRY_DSN) {
    //   Sentry.captureException(reason);
    // }

    // Don't exit process in production - let monitoring catch it
    if (process.env.NODE_ENV === 'development') {
      process.exit(1);
    }
  });

  process.on('uncaughtException', (error: Error) => {
    log.error('Uncaught Exception', {
      message: error.message,
      stack: error.stack,
    });

    // TODO: Send to error tracking
    // if (process.env.SENTRY_DSN) {
    //   Sentry.captureException(error);
    // }

    // Uncaught exceptions are fatal - exit process
    process.exit(1);
  });
}
