import { Component, type ErrorInfo, type ReactNode } from "react";
import { motion } from "framer-motion";
import { RefreshCw, ArrowLeft, Shield, Wifi, Server, Bug } from "lucide-react";
import { Button } from "@/components/ui/button";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

function classifyError(error: Error | null): {
  icon: typeof Shield;
  title: string;
  description: string;
  gradient: string;
  hint: string;
} {
  const msg = error?.message?.toLowerCase() ?? "";

  if (msg.includes("fetch") || msg.includes("network") || msg.includes("timeout")) {
    return {
      icon: Wifi,
      title: "Connection interrupted",
      description: "We lost the signal. Your data is safe — this is just a network hiccup.",
      gradient: "from-amber-500/20 to-orange-500/20",
      hint: "Check your connection and try again",
    };
  }
  if (msg.includes("401") || msg.includes("403") || msg.includes("unauthorized") || msg.includes("forbidden")) {
    return {
      icon: Shield,
      title: "Access restricted",
      description: "Your session may have expired or you need different permissions.",
      gradient: "from-blue-500/20 to-indigo-500/20",
      hint: "Try logging in again",
    };
  }
  if (msg.includes("500") || msg.includes("server") || msg.includes("internal")) {
    return {
      icon: Server,
      title: "Server taking a breather",
      description: "Our systems are recovering. This usually resolves itself in a moment.",
      gradient: "from-red-500/20 to-pink-500/20",
      hint: "Wait a moment, then retry",
    };
  }
  return {
    icon: Bug,
    title: "Unexpected glitch",
    description: "Something didn't go as planned. Our team has been notified.",
    gradient: "from-violet-500/20 to-purple-500/20",
    hint: "Try refreshing the page",
  };
}

function ErrorFallbackUI({
  error,
  onReset,
  onReload,
}: {
  error: Error | null;
  onReset: () => void;
  onReload: () => void;
}) {
  const classified = classifyError(error);
  const Icon = classified.icon;

  return (
    <div className="flex items-center justify-center min-h-[60vh] p-6" role="alert">
      <motion.div
        initial={{ opacity: 0, y: 20, scale: 0.95 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
        className="max-w-md w-full text-center space-y-5"
      >
        {/* Animated icon with pulse ring */}
        <div className="relative mx-auto w-20 h-20 flex items-center justify-center">
          <motion.div
            className={`absolute inset-0 rounded-full bg-gradient-to-br ${classified.gradient} blur-xl`}
            animate={{ scale: [1, 1.2, 1], opacity: [0.5, 0.3, 0.5] }}
            transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
          />
          <motion.div
            className={`relative z-10 w-16 h-16 rounded-2xl bg-gradient-to-br ${classified.gradient} backdrop-blur-sm border border-white/10 flex items-center justify-center`}
            animate={{ y: [0, -4, 0] }}
            transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
          >
            <Icon className="h-7 w-7 text-foreground" />
          </motion.div>
        </div>

        {/* Title + description */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15, duration: 0.4 }}
        >
          <h2 className="text-xl font-bold tracking-tight text-foreground">{classified.title}</h2>
          <p className="text-sm text-muted-foreground mt-2 leading-relaxed">{classified.description}</p>
        </motion.div>

        {/* Hint badge */}
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.3, duration: 0.3 }}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-muted/60 border border-border/50 text-xs text-muted-foreground"
        >
          <span className="w-1.5 h-1.5 rounded-full bg-primary animate-live-dot" />
          {classified.hint}
        </motion.div>

        {/* Action buttons */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4, duration: 0.3 }}
          className="flex items-center justify-center gap-3 pt-1"
        >
          <Button variant="outline" size="sm" onClick={onReset} className="group">
            <ArrowLeft className="h-3.5 w-3.5 mr-1.5 group-hover:-translate-x-0.5 transition-transform" />
            Go back
          </Button>
          <Button size="sm" onClick={onReload} className="group relative overflow-hidden">
            <span className="absolute inset-0 bg-gradient-to-r from-primary/0 via-primary-foreground/10 to-primary/0 translate-x-[-200%] group-hover:translate-x-[200%] transition-transform duration-700" />
            <RefreshCw className="h-3.5 w-3.5 mr-1.5 group-hover:rotate-180 transition-transform duration-500" />
            Reload page
          </Button>
        </motion.div>

        {/* Error code (dev only) */}
        {process.env.NODE_ENV === "development" && error && (
          <motion.details
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.6 }}
            className="text-left"
          >
            <summary className="text-xs text-muted-foreground/60 cursor-pointer hover:text-muted-foreground transition-colors">
              Technical details
            </summary>
            <pre className="mt-2 max-h-32 overflow-auto rounded-lg bg-muted/30 border border-border/50 p-3 text-xs text-muted-foreground font-mono">
              {error.message}
              {error.stack && `\n\n${error.stack}`}
            </pre>
          </motion.details>
        )}
      </motion.div>
    </div>
  );
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    if (process.env.NODE_ENV === "development") {
      console.error("[ErrorBoundary]", error, info.componentStack);
    }
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  private handleReload = () => {
    window.location.reload();
  };

  render() {
    if (!this.state.hasError) {
      return this.props.children;
    }

    if (this.props.fallback) {
      return this.props.fallback;
    }

    return <ErrorFallbackUI error={this.state.error} onReset={this.handleReset} onReload={this.handleReload} />;
  }
}
