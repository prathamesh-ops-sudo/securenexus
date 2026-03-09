import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { usePageTitle } from "@/hooks/use-page-title";
import { useOrgContext } from "@/hooks/use-org-context";
import {
  Globe,
  AlertTriangle,
  RefreshCw,
  Plus,
  CheckCircle2,
  XCircle,
  Clock,
  Shield,
  Loader2,
  Trash2,
  Copy,
  Search,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Label } from "@/components/ui/label";

interface DomainVerification {
  id: string;
  domain: string;
  status: "pending" | "verified" | "failed";
  verificationType: "dns_txt" | "dns_cname" | "meta_tag";
  verificationToken: string;
  autoJoinEnabled: boolean;
  createdAt: string;
  verifiedAt?: string;
}

export default function DomainAutoJoinPage() {
  usePageTitle("Domain Auto-Join & DNS Verification");
  const { toast } = useToast();
  const { currentOrgId } = useOrgContext();
  const [showAdd, setShowAdd] = useState(false);
  const [newDomain, setNewDomain] = useState("");

  const domainsKey = [`/api/orgs/${currentOrgId}/domains`];

  const {
    data: domains,
    isLoading,
    isError,
    refetch,
  } = useQuery<DomainVerification[]>({
    queryKey: domainsKey,
    queryFn: () => apiRequest("GET", `/api/orgs/${currentOrgId}/domains`).then((r) => r.json()),
    enabled: !!currentOrgId,
  });

  const addMutation = useMutation({
    mutationFn: () => apiRequest("POST", `/api/orgs/${currentOrgId}/domains`, { domain: newDomain }),
    onSuccess: () => {
      toast({ title: "Domain added for verification" });
      queryClient.invalidateQueries({ queryKey: domainsKey });
      setNewDomain("");
      setShowAdd(false);
    },
    onError: () => toast({ title: "Failed to add domain", variant: "destructive" }),
  });

  const verifyMutation = useMutation({
    mutationFn: (id: string) => apiRequest("POST", `/api/orgs/${currentOrgId}/domains/${id}/verify`),
    onSuccess: () => {
      toast({ title: "Domain verification initiated" });
      queryClient.invalidateQueries({ queryKey: domainsKey });
    },
    onError: () => toast({ title: "Verification failed", variant: "destructive" }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiRequest("DELETE", `/api/orgs/${currentOrgId}/domains/${id}`),
    onSuccess: () => {
      toast({ title: "Domain removed" });
      queryClient.invalidateQueries({ queryKey: domainsKey });
    },
    onError: () => toast({ title: "Failed to remove domain", variant: "destructive" }),
  });

  const list = Array.isArray(domains) ? domains : [];

  const statusIcon = (s: string) => {
    if (s === "verified") return <CheckCircle2 className="h-4 w-4 text-green-500" />;
    if (s === "failed") return <XCircle className="h-4 w-4 text-red-500" />;
    return <Clock className="h-4 w-4 text-yellow-500" />;
  };

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="space-y-3">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-24" />
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
            <p className="text-muted-foreground">Failed to load domain settings</p>
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
            <Globe className="h-6 w-6" /> Domain Auto-Join & DNS Verification
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Verify domain ownership and enable automatic team joining for verified domains
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> Refresh
          </Button>
          <Button size="sm" onClick={() => setShowAdd(!showAdd)}>
            <Plus className="mr-2 h-4 w-4" /> Add Domain
          </Button>
        </div>
      </div>

      {showAdd && (
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Add Domain</CardTitle>
            <CardDescription>Enter your domain to begin DNS verification</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label>Domain</Label>
              <Input placeholder="example.com" value={newDomain} onChange={(e) => setNewDomain(e.target.value)} />
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setShowAdd(false)}>
                Cancel
              </Button>
              <Button onClick={() => addMutation.mutate()} disabled={!newDomain.trim() || addMutation.isPending}>
                {addMutation.isPending ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <Plus className="mr-2 h-4 w-4" />
                )}
                Add
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Globe className="h-5 w-5 text-primary" />
            <div>
              <p className="text-2xl font-bold">{list.length}</p>
              <p className="text-xs text-muted-foreground">Total Domains</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <CheckCircle2 className="h-5 w-5 text-green-500" />
            <div>
              <p className="text-2xl font-bold">{list.filter((d) => d.status === "verified").length}</p>
              <p className="text-xs text-muted-foreground">Verified</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-2">
            <Clock className="h-5 w-5 text-yellow-500" />
            <div>
              <p className="text-2xl font-bold">{list.filter((d) => d.status === "pending").length}</p>
              <p className="text-xs text-muted-foreground">Pending</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {list.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center py-12 gap-3">
            <Globe className="h-8 w-8 text-muted-foreground" />
            <p className="text-muted-foreground">No domains configured</p>
            <Button size="sm" onClick={() => setShowAdd(true)}>
              <Plus className="mr-2 h-4 w-4" /> Add First Domain
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {list.map((d) => (
            <Card key={d.id}>
              <CardContent className="py-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-3">
                    {statusIcon(d.status)}
                    <div>
                      <p className="font-medium text-sm">{d.domain}</p>
                      <p className="text-xs text-muted-foreground">
                        {d.verificationType.replace(/_/g, " ").toUpperCase()} verification &middot; Added{" "}
                        {new Date(d.createdAt).toLocaleDateString()}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {d.autoJoinEnabled && (
                      <Badge variant="outline">
                        <Shield className="mr-1 h-3 w-3" /> Auto-Join
                      </Badge>
                    )}
                    <Badge
                      variant={
                        d.status === "verified" ? "default" : d.status === "failed" ? "destructive" : "secondary"
                      }
                    >
                      {d.status}
                    </Badge>
                    {d.status === "pending" && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => verifyMutation.mutate(d.id)}
                        disabled={verifyMutation.isPending}
                      >
                        {verifyMutation.isPending ? (
                          <Loader2 className="mr-1 h-3 w-3 animate-spin" />
                        ) : (
                          <Search className="mr-1 h-3 w-3" />
                        )}
                        Verify
                      </Button>
                    )}
                    <Button
                      variant="ghost"
                      size="icon"
                      className="text-destructive"
                      onClick={() => deleteMutation.mutate(d.id)}
                      disabled={deleteMutation.isPending}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
                {d.status === "pending" && (
                  <div className="bg-muted p-3 rounded text-sm">
                    <p className="text-xs font-medium text-muted-foreground mb-1">DNS Record to add:</p>
                    <div className="flex items-center gap-2">
                      <code className="text-xs bg-background p-1 rounded flex-1 font-mono">
                        TXT _securenexus-verify.{d.domain} = {d.verificationToken}
                      </code>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => {
                          navigator.clipboard.writeText(`TXT _securenexus-verify.${d.domain} = ${d.verificationToken}`);
                          toast({ title: "Copied to clipboard" });
                        }}
                      >
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
