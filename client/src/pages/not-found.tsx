import { Link } from "wouter";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { AlertCircle } from "lucide-react";

export default function NotFound() {
  return (
    <div className="min-h-full w-full flex items-center justify-center bg-background p-6">
      <Card className="w-full max-w-md mx-4 border-border/60 bg-card">
        <CardContent className="pt-6">
          <div className="flex mb-4 gap-2 items-center">
            <AlertCircle className="h-8 w-8 text-muted-foreground" />
            <h1 className="text-2xl font-bold text-foreground">Page not found</h1>
          </div>
          <p className="mt-4 text-sm text-muted-foreground">We couldn&apos;t find the page you requested.</p>
          <Button asChild className="mt-6">
            <Link href="/">Return to dashboard</Link>
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
