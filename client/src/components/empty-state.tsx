import { type LucideIcon, RefreshCw, AlertCircle, Inbox } from "lucide-react";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";

interface EmptyStateAction {
  label: string;
  onClick: () => void;
  icon?: LucideIcon;
  variant?: "default" | "outline" | "secondary" | "ghost";
}

interface EmptyStateProps {
  icon: LucideIcon;
  title: string;
  description: string;
  action?: EmptyStateAction;
  secondaryAction?: EmptyStateAction;
  className?: string;
  compact?: boolean;
}

export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  secondaryAction,
  className = "",
  compact = false,
}: EmptyStateProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      className={`flex flex-col items-center justify-center text-center ${compact ? "py-8 px-4" : "py-16 px-6"} ${className}`}
      role="status"
      aria-label={title}
    >
      <motion.div
        initial={{ scale: 0.8 }}
        animate={{ scale: 1 }}
        transition={{ delay: 0.1, duration: 0.3, type: "spring", stiffness: 200 }}
        className="relative"
      >
        <div
          className={`rounded-2xl bg-gradient-to-br from-muted/80 to-muted/40 border border-border/50 ${compact ? "p-3 mb-3" : "p-5 mb-5"} backdrop-blur-sm`}
        >
          <Icon className={`${compact ? "h-6 w-6" : "h-8 w-8"} text-muted-foreground`} aria-hidden="true" />
        </div>
        {/* Subtle decorative dots */}
        <div className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-primary/20 animate-live-dot" />
        <div
          className="absolute -bottom-1 -left-1 w-1.5 h-1.5 rounded-full bg-primary/15"
          style={{ animationDelay: "0.5s" }}
        />
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.15, duration: 0.3 }}
      >
        <h3 className={`font-semibold ${compact ? "text-sm" : "text-base"} mb-1`}>{title}</h3>
        <p className={`text-muted-foreground max-w-sm ${compact ? "text-xs" : "text-sm"} leading-relaxed mb-4`}>
          {description}
        </p>
      </motion.div>

      {(action || secondaryAction) && (
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.25, duration: 0.3 }}
          className="flex items-center gap-2"
        >
          {action && (
            <Button
              onClick={action.onClick}
              variant={action.variant || "default"}
              size={compact ? "sm" : "default"}
              aria-label={action.label}
              className="group"
            >
              {action.icon && (
                <action.icon className="h-4 w-4 mr-1.5 group-hover:scale-110 transition-transform" aria-hidden="true" />
              )}
              {action.label}
            </Button>
          )}
          {secondaryAction && (
            <Button
              onClick={secondaryAction.onClick}
              variant={secondaryAction.variant || "outline"}
              size={compact ? "sm" : "default"}
              aria-label={secondaryAction.label}
            >
              {secondaryAction.icon && <secondaryAction.icon className="h-4 w-4 mr-1.5" aria-hidden="true" />}
              {secondaryAction.label}
            </Button>
          )}
        </motion.div>
      )}
    </motion.div>
  );
}

export function EmptyChartState({
  icon: Icon,
  message,
  height = "200px",
}: {
  icon: LucideIcon;
  message: string;
  height?: string;
}) {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col items-center justify-center gap-3 text-muted-foreground"
      style={{ height }}
      role="status"
      aria-label={message}
    >
      <div className="relative">
        <div className="absolute inset-0 rounded-full bg-muted/50 blur-lg" />
        <div className="relative p-3 rounded-xl bg-muted/30 border border-border/30">
          <Icon className="h-5 w-5 opacity-60" aria-hidden="true" />
        </div>
      </div>
      <span className="text-xs font-medium">{message}</span>
    </motion.div>
  );
}

interface ErrorStateProps {
  title?: string;
  message?: string;
  onRetry?: () => void;
  compact?: boolean;
  className?: string;
  icon?: LucideIcon;
}

export function ErrorState({
  title = "Something went wrong",
  message = "Failed to load data. Please try again.",
  onRetry,
  compact = false,
  className = "",
  icon: CustomIcon,
}: ErrorStateProps) {
  const Icon = CustomIcon || AlertCircle;

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      className={`flex flex-col items-center justify-center text-center ${compact ? "py-8 px-4" : "py-16 px-6"} ${className}`}
      role="alert"
      aria-label={title}
    >
      {/* Animated error icon */}
      <div className="relative mx-auto mb-4">
        <motion.div
          className="absolute inset-0 rounded-full bg-gradient-to-br from-destructive/20 to-red-500/10 blur-xl"
          animate={{ scale: [1, 1.15, 1], opacity: [0.4, 0.2, 0.4] }}
          transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
        />
        <motion.div
          initial={{ scale: 0.8, rotate: -10 }}
          animate={{ scale: 1, rotate: 0 }}
          transition={{ duration: 0.4, type: "spring", stiffness: 200 }}
          className={`relative ${compact ? "p-3" : "p-4"} rounded-2xl bg-gradient-to-br from-destructive/15 to-red-500/10 border border-destructive/20 backdrop-blur-sm`}
        >
          <Icon className={`${compact ? "h-6 w-6" : "h-7 w-7"} text-destructive`} aria-hidden="true" />
        </motion.div>
      </div>

      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1, duration: 0.3 }}
      >
        <h3 className={`font-bold ${compact ? "text-sm" : "text-base"} mb-1`}>{title}</h3>
        <p className={`text-muted-foreground max-w-sm ${compact ? "text-xs" : "text-sm"} leading-relaxed mb-4`}>
          {message}
        </p>
      </motion.div>

      {onRetry && (
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2, duration: 0.3 }}
        >
          <Button
            onClick={onRetry}
            variant="outline"
            size={compact ? "sm" : "default"}
            aria-label="Retry loading"
            className="group border-destructive/20 hover:border-destructive/40 hover:bg-destructive/5 transition-all"
          >
            <RefreshCw
              className="h-3.5 w-3.5 mr-1.5 group-hover:rotate-180 transition-transform duration-500"
              aria-hidden="true"
            />
            Try Again
          </Button>
        </motion.div>
      )}
    </motion.div>
  );
}

/* Re-export a PageLoadingState for consistent loading across pages */
export function PageLoadingState({ message = "Loading..." }: { message?: string }) {
  return (
    <div className="flex flex-col items-center justify-center min-h-[40vh] gap-4">
      <div className="relative">
        <motion.div
          className="w-10 h-10 rounded-full border-2 border-primary/30 border-t-primary"
          animate={{ rotate: 360 }}
          transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
        />
        <motion.div
          className="absolute inset-0 rounded-full bg-primary/10 blur-lg"
          animate={{ scale: [1, 1.3, 1], opacity: [0.3, 0.1, 0.3] }}
          transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
        />
      </div>
      <p className="text-sm text-muted-foreground animate-fade-in">{message}</p>
    </div>
  );
}

/* Skeleton loader for content areas */
export function ContentSkeleton({ rows = 3, className = "" }: { rows?: number; className?: string }) {
  return (
    <div className={`space-y-3 animate-fade-in ${className}`} role="status" aria-label="Loading content">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center gap-3" style={{ animationDelay: `${i * 100}ms` }}>
          <div className="h-10 w-10 rounded-lg bg-muted/60 animate-pulse" />
          <div className="flex-1 space-y-2">
            <div
              className="h-3 rounded-full bg-muted/60 animate-pulse"
              style={{ width: `${70 + Math.random() * 30}%` }}
            />
            <div
              className="h-2.5 rounded-full bg-muted/40 animate-pulse"
              style={{ width: `${40 + Math.random() * 30}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}
