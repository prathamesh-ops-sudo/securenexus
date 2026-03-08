import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  Target,
  AlertTriangle,
  RefreshCw,
  Search,
  Globe,
  Shield,
  Users,
  Calendar,
  ExternalLink,
  Eye,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";

interface Campaign {
  id: string;
  name: string;
  aliases: string[];
  description: string;
  firstSeen: string;
  lastSeen: string;
  targetSectors: string[];
  targetRegions: string[];
  techniques: string[];
  iocCount: number;
  confidence: number;
  status: "active" | "dormant" | "historical";
}

export default function CampaignViewerPage() {
  usePageTitle("Campaign / Threat Group Viewer");
  const [search, setSearch] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const {
    data: campaigns,
    isLoading,
    isError,
    refetch,
  } = useQuery<Campaign[]>({
    queryKey: ["/api/campaigns"],
    queryFn: () => apiRequest("GET", "/api/campaigns").then((r) => r.json()),
  });

  const list = Array.isArray(campaigns) ? campaigns : [];
  const filtered = list.filter(
    (c) =>
      !search ||
      c.name.toLowerCase().includes(search.toLowerCase()) ||
      c.aliases.some((a) => a.toLowerCase().includes(search.toLowerCase())),
  );

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="space-y-3">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-28" />
          ))}
        </div>
      </div>
    );
  }

  if (isError) {
    return (
      <div className="p-6">
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 gap-3">
            <AlertTriangle className="h-8 w-8 text-destructive" />
            <p className="text-muted-foreground">Failed to load campaigns</p>
            <Button variant="outline" onClick={() => refetch()}>
              <RefreshCw className="mr-2 h-4 w-4" /> Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Target className="h-6 w-6" /> Campaign / Threat Group Viewer
          </h1>
          <p className="text-muted-foreground text-sm mt-1">Track threat campaigns, actor groups, and their TTPs</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="mr-2 h-4 w-4" /> Refresh
        </Button>
      </div>

      <div className="flex gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search campaigns or aliases..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Target className="h-5 w-5 text-red-500" />
            <div>
              <p className="text-2xl font-bold">{list.filter((c) => c.status === "active").length}</p>
              <p className="text-xs text-muted-foreground">Active Campaigns</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Shield className="h-5 w-5 text-yellow-500" />
            <div>
              <p className="text-2xl font-bold">{list.filter((c) => c.status === "dormant").length}</p>
              <p className="text-xs text-muted-foreground">Dormant</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Globe className="h-5 w-5 text-blue-500" />
            <div>
              <p className="text-2xl font-bold">{list.length}</p>
              <p className="text-xs text-muted-foreground">Total Tracked</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {filtered.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center py-12 gap-3">
            <Target className="h-8 w-8 text-muted-foreground" />
            <p className="text-muted-foreground">
              {search ? "No campaigns match your search" : "No campaigns tracked yet"}
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {filtered.map((c) => (
            <Card
              key={c.id}
              className="transition-all hover:shadow-md cursor-pointer"
              onClick={() => setExpandedId(expandedId === c.id ? null : c.id)}
            >
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Target className="h-5 w-5 text-primary" />
                    <div>
                      <CardTitle className="text-base">{c.name}</CardTitle>
                      {c.aliases.length > 0 && (
                        <CardDescription className="text-xs">Also known as: {c.aliases.join(", ")}</CardDescription>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge
                      variant={c.status === "active" ? "destructive" : c.status === "dormant" ? "secondary" : "outline"}
                    >
                      {c.status}
                    </Badge>
                    <Badge variant="outline">{c.confidence}% confidence</Badge>
                    <Badge variant="outline">{c.iocCount} IOCs</Badge>
                  </div>
                </div>
              </CardHeader>
              {expandedId === c.id && (
                <CardContent className="space-y-3">
                  <p className="text-sm text-muted-foreground">{c.description}</p>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">
                        <Calendar className="inline h-3 w-3 mr-1" /> Timeline
                      </p>
                      <p className="text-sm">
                        {new Date(c.firstSeen).toLocaleDateString()} &mdash; {new Date(c.lastSeen).toLocaleDateString()}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">
                        <Globe className="inline h-3 w-3 mr-1" /> Target Regions
                      </p>
                      <div className="flex flex-wrap gap-1">
                        {c.targetRegions.map((r) => (
                          <Badge key={r} variant="outline" className="text-xs">
                            {r}
                          </Badge>
                        ))}
                      </div>
                    </div>
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">
                        <Users className="inline h-3 w-3 mr-1" /> Target Sectors
                      </p>
                      <div className="flex flex-wrap gap-1">
                        {c.targetSectors.map((s) => (
                          <Badge key={s} variant="outline" className="text-xs">
                            {s}
                          </Badge>
                        ))}
                      </div>
                    </div>
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">
                        <Shield className="inline h-3 w-3 mr-1" /> Techniques
                      </p>
                      <div className="flex flex-wrap gap-1">
                        {c.techniques.map((t) => (
                          <Badge key={t} variant="secondary" className="text-xs font-mono">
                            {t}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </div>
                </CardContent>
              )}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
