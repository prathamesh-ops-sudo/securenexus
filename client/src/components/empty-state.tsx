import { type LucideIcon } from "lucide-react";
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
    <div
      className={`flex flex-col items-center justify-center text-center ${compact ? "py-8 px-4" : "py-16 px-6"} ${className}`}
      role="status"
      aria-label={title}
    >
      <div className={`rounded-full bg-muted/50 ${compact ? "p-3 mb-3" : "p-4 mb-4"} ring-1 ring-border/50`}>
        <Icon
          className={`${compact ? "h-6 w-6" : "h-8 w-8"} text-muted-foreground`}
          aria-hidden="true"
        />
      </div>
      <h3 className={`font-semibold ${compact ? "text-sm" : "text-base"} mb-1`}>
        {title}
      </h3>
      <p className={`text-muted-foreground max-w-sm ${compact ? "text-xs" : "text-sm"} mb-4`}>
        {description}
      </p>
      {(action || secondaryAction) && (
        <div className="flex items-center gap-2">
          {action && (
            <Button
              onClick={action.onClick}
              variant={action.variant || "default"}
              size={compact ? "sm" : "default"}
              aria-label={action.label}
            >
              {action.icon && <action.icon className="h-4 w-4 mr-1.5" aria-hidden="true" />}
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
        </div>
      )}
    </div>
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
    <div
      className="flex flex-col items-center justify-center gap-2 text-muted-foreground"
      style={{ height }}
      role="status"
      aria-label={message}
    >
      <Icon className="h-6 w-6 opacity-50" aria-hidden="true" />
      <span className="text-xs">{message}</span>
    </div>
  );
}
