import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import {
  BookOpen,
  Search,
  Star,
  Download,
  Filter,
  Layers,
  Shield,
  Zap,
  Bug,
  Cloud,
  UserX,
  Target,
  ChevronRight,
  Loader2,
  Plus,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";

export default function PlaybookTemplatesPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [selectedTemplate, setSelectedTemplate] = useState<string | null>(null);

  const { data: templates, isLoading } = useQuery({
    queryKey: ["/api/playbook-templates", search, selectedCategory],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (search) params.set("search", search);
      if (selectedCategory) params.set("category", selectedCategory);
      const r = await apiRequest("GET", `/api/playbook-templates?${params.toString()}`);
      return r.json();
    },
  });

  const { data: categories } = useQuery({
    queryKey: ["/api/playbook-templates/categories"],
    queryFn: async () => {
      const r = await apiRequest("GET", "/api/playbook-templates/categories");
      return r.json();
    },
  });

  const { data: detail } = useQuery({
    queryKey: ["/api/playbook-templates", selectedTemplate],
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/playbook-templates/${selectedTemplate}`);
      return r.json();
    },
    enabled: !!selectedTemplate,
  });

  const deployMutation = useMutation({
    mutationFn: async (id: string) => {
      const r = await apiRequest("POST", `/api/playbook-templates/${id}/deploy`);
      return r.json();
    },
    onSuccess: () => {
      toast({ title: "Template Deployed", description: "Playbook created from template." });
      queryClient.invalidateQueries({ queryKey: ["/api/playbook-templates"] });
    },
    onError: () => toast({ title: "Deploy Failed", variant: "destructive" }),
  });

  const templateList = Array.isArray(templates) ? templates : (templates as any)?.data || [];
  const categoryList = Array.isArray(categories) ? categories : [];
  const templateDetail = detail as any;

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[1, 2, 3, 4, 5, 6].map((i) => (
            <Skeleton key={i} className="h-48" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <BookOpen className="h-6 w-6 text-purple-400" />
            Playbook Templates
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Pre-built response playbooks for common security scenarios
          </p>
        </div>
      </div>

      <div className="flex flex-wrap gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search templates..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-10"
          />
        </div>
        <div className="flex gap-2 flex-wrap">
          <Button
            size="sm"
            variant={selectedCategory === null ? "default" : "outline"}
            onClick={() => setSelectedCategory(null)}
          >
            All
          </Button>
          {categoryList.map((cat: string) => (
            <Button
              key={cat}
              size="sm"
              variant={selectedCategory === cat ? "default" : "outline"}
              onClick={() => setSelectedCategory(cat)}
            >
              <CategoryIcon category={cat} />
              <span className="ml-1">{cat}</span>
            </Button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-4">
          {templateList.length === 0 && (
            <Card className="border-dashed border-border bg-card/30">
              <CardContent className="py-12 text-center">
                <BookOpen className="h-12 w-12 text-muted-foreground mx-auto mb-3" />
                <p className="text-muted-foreground">No templates match your search</p>
              </CardContent>
            </Card>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {templateList.map((tpl: any) => (
              <Card
                key={tpl.id}
                onClick={() => setSelectedTemplate(tpl.id)}
                className={`cursor-pointer transition-all hover:border-purple-500/30 ${selectedTemplate === tpl.id ? "border-purple-400 bg-purple-500/5" : "border-border bg-card/50"}`}
              >
                <CardContent className="p-4">
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <CategoryIcon category={tpl.category} />
                      <span className="text-sm font-medium">{tpl.name}</span>
                    </div>
                    <SeverityBadge severity={tpl.severity} />
                  </div>
                  <p className="text-xs text-muted-foreground line-clamp-2 mb-3">{tpl.description}</p>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="flex items-center gap-1">
                        <Star className="h-3 w-3 text-yellow-400" />
                        <span className="text-xs">{tpl.rating}</span>
                      </div>
                      <span className="text-xs text-muted-foreground">{tpl.usageCount} deployments</span>
                    </div>
                    <div className="flex gap-1">
                      {(tpl.tags || []).slice(0, 2).map((tag: string) => (
                        <Badge key={tag} variant="outline" className="text-xs">
                          {tag}
                        </Badge>
                      ))}
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>

        <div>
          {!selectedTemplate && (
            <Card className="border-dashed border-border bg-card/30">
              <CardContent className="py-12 text-center">
                <Layers className="h-10 w-10 text-muted-foreground mx-auto mb-2" />
                <p className="text-sm text-muted-foreground">Select a template to view details</p>
              </CardContent>
            </Card>
          )}

          {selectedTemplate && templateDetail && (
            <Card className="border-purple-500/20 bg-card/50 sticky top-6">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg">{templateDetail.name}</CardTitle>
                  <Badge variant="outline">v{templateDetail.version}</Badge>
                </div>
                <p className="text-sm text-muted-foreground">{templateDetail.description}</p>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center gap-2 text-sm">
                  <span className="text-muted-foreground">By:</span>
                  <span>{templateDetail.author}</span>
                </div>

                <div>
                  <h3 className="text-sm font-semibold mb-2">Steps ({templateDetail.steps?.length || 0})</h3>
                  <div className="space-y-2">
                    {(templateDetail.steps || []).map((step: any, i: number) => (
                      <div key={step.id || i} className="flex items-center gap-2 p-2 rounded bg-background/50 text-sm">
                        <span className="flex items-center justify-center w-5 h-5 rounded-full bg-purple-500/20 text-purple-400 text-xs font-bold">
                          {step.order || i + 1}
                        </span>
                        <span className="flex-1">{step.name}</span>
                        <StepTypeBadge type={step.type} />
                      </div>
                    ))}
                  </div>
                </div>

                <div className="flex flex-wrap gap-1">
                  {(templateDetail.tags || []).map((tag: string) => (
                    <Badge key={tag} variant="outline" className="text-xs">
                      {tag}
                    </Badge>
                  ))}
                </div>

                <Button
                  className="w-full bg-purple-600 hover:bg-purple-700"
                  onClick={() => deployMutation.mutate(templateDetail.id)}
                  disabled={deployMutation.isPending}
                >
                  {deployMutation.isPending ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <Download className="h-4 w-4 mr-2" />
                  )}
                  Deploy as Playbook
                </Button>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

function CategoryIcon({ category }: { category: string }) {
  switch (category) {
    case "Incident Response":
      return <Shield className="h-4 w-4 text-red-400" />;
    case "Email Security":
      return <Zap className="h-4 w-4 text-yellow-400" />;
    case "Cloud Security":
      return <Cloud className="h-4 w-4 text-blue-400" />;
    case "Insider Threat":
      return <UserX className="h-4 w-4 text-orange-400" />;
    case "Vulnerability Management":
      return <Bug className="h-4 w-4 text-green-400" />;
    default:
      return <Target className="h-4 w-4 text-cyan-400" />;
  }
}

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400",
    high: "bg-orange-500/20 text-orange-400",
    medium: "bg-yellow-500/20 text-yellow-400",
    low: "bg-green-500/20 text-green-400",
  };
  return <Badge className={`text-xs ${colors[severity] || colors.medium}`}>{severity}</Badge>;
}

function StepTypeBadge({ type }: { type: string }) {
  const colors: Record<string, string> = {
    automated: "bg-cyan-500/20 text-cyan-400",
    manual: "bg-yellow-500/20 text-yellow-400",
    approval: "bg-purple-500/20 text-purple-400",
    notification: "bg-blue-500/20 text-blue-400",
  };
  return <Badge className={`text-xs ${colors[type] || "bg-gray-500/20 text-gray-400"}`}>{type}</Badge>;
}
