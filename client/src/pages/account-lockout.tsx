import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { usePageTitle } from "@/hooks/use-page-title";
import {
  Lock,
  Unlock,
  RefreshCw,
  Loader2,
  ShieldAlert,
  Clock,
  Globe,
  Users,
  AlertTriangle,
  Search,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { LockUnlockIcon } from "@/components/ui/animated-state-icons";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";

interface LockedAccount {
  id: string;
  email: string | null;
  lockedUntil: string | null;
  failedLoginCount: number;
  lastFailedAt: string | null;
  lastFailedIp: string | null;
}

interface FailedAttempt {
  id: string;
  userId: string | null;
  email: string;
  ipAddress: string;
  userAgent: string | null;
  reason: string;
  attemptedAt: string;
}

interface FailedLoginStats {
  totalAttempts24h: number;
  lockedAccountsCount: number;
  topIps: Array<{ ip: string; count: number }>;
}

function ensureArray<T>(val: unknown): T[] {
  if (Array.isArray(val)) return val as T[];
  if (val && typeof val === "object" && "data" in val) {
    const inner = (val as Record<string, unknown>).data;
    if (Array.isArray(inner)) return inner as T[];
  }
  return [];
}

function unwrapData<T>(val: unknown): T {
  if (val && typeof val === "object" && "data" in val) {
    return (val as Record<string, unknown>).data as T;
  }
  return val as T;
}

function formatDate(d: string | null): string {
  if (!d) return "\u2014";
  return new Date(d).toLocaleString();
}

function timeRemaining(lockedUntil: string | null): string {
  if (!lockedUntil) return "\u2014";
  const diff = new Date(lockedUntil).getTime() - Date.now();
  if (diff <= 0) return "Expired";
  const min = Math.ceil(diff / 60_000);
  if (min < 60) return `${min}m`;
  return `${Math.floor(min / 60)}h ${min % 60}m`;
}

export default function AccountLockoutPage() {
  usePageTitle("Account Lockout");
  const { toast } = useToast();
  const qc = useQueryClient();
  const [searchTerm, setSearchTerm] = useState("");
  const [historyPage, setHistoryPage] = useState(0);
  const pageSize = 50;

  const statsQuery = useQuery<FailedLoginStats>({
    queryKey: ["/api/platform-admin/failed-login-stats"],
    refetchInterval: 30_000,
    select: unwrapData<FailedLoginStats>,
  });

  const lockedQuery = useQuery<LockedAccount[]>({
    queryKey: ["/api/platform-admin/locked-accounts"],
    refetchInterval: 15_000,
    select: ensureArray<LockedAccount>,
  });

  const historyQuery = useQuery<{ attempts: FailedAttempt[]; total: number }>({
    queryKey: ["/api/platform-admin/failed-login-history", historyPage],
    queryFn: async () => {
      const headers: Record<string, string> = {};
      try {
        const activeOrgId = localStorage.getItem("securenexus.activeOrgId");
        if (activeOrgId) headers["X-Org-Id"] = activeOrgId;
      } catch {
        /* localStorage unavailable */
      }
      const rawRes = await fetch(
        `/api/platform-admin/failed-login-history?limit=${pageSize}&offset=${historyPage * pageSize}`,
        { credentials: "include", headers },
      );
      if (!rawRes.ok) throw new Error(`${rawRes.status}: ${rawRes.statusText}`);
      const json = await rawRes.json();
      const data = json?.data ?? json;
      const meta = json?.meta ?? {};
      return {
        attempts: Array.isArray(data) ? data : [],
        total: meta.total ?? (Array.isArray(data) ? data.length : 0),
      };
    },
    refetchInterval: 30_000,
  });

  const unlockMutation = useMutation({
    mutationFn: async (userId: string) => {
      await apiRequest("POST", `/api/platform-admin/unlock-account/${userId}`);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/platform-admin/locked-accounts"] });
      qc.invalidateQueries({ queryKey: ["/api/platform-admin/failed-login-stats"] });
      toast({ title: "Account unlocked", description: "The account has been unlocked successfully." });
    },
    onError: () => {
      toast({ title: "Unlock failed", description: "Failed to unlock the account.", variant: "destructive" });
    },
  });

  const stats = statsQuery.data;
  const locked = lockedQuery.data ?? [];
  const history = historyQuery.data;
  const filteredLocked = locked.filter(
    (a) => !searchTerm || (a.email || "").toLowerCase().includes(searchTerm.toLowerCase()),
  );
  const filteredHistory = (history?.attempts ?? []).filter(
    (a) => !searchTerm || a.email.toLowerCase().includes(searchTerm.toLowerCase()),
  );

  const isLoading = statsQuery.isPending && lockedQuery.isPending;

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <Skeleton className="h-8 w-64" />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-28 rounded-lg" />
          ))}
        </div>
        <Skeleton className="h-64 rounded-lg" />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Lock className="h-6 w-6 text-red-500" />
            Account Lockout Dashboard
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Monitor failed login attempts, locked accounts, and suspicious IP activity
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            qc.invalidateQueries({ queryKey: ["/api/platform-admin/failed-login-stats"] });
            qc.invalidateQueries({ queryKey: ["/api/platform-admin/locked-accounts"] });
            qc.invalidateQueries({ queryKey: ["/api/platform-admin/failed-login-history"] });
            toast({ title: "Refreshed" });
          }}
        >
          <RefreshCw className="h-4 w-4 mr-1" /> Refresh
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription className="flex items-center gap-1">
              <ShieldAlert className="h-4 w-4" /> Failed Attempts (24h)
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{stats?.totalAttempts24h ?? 0}</div>
            <p className="text-xs text-muted-foreground mt-1">Total failed login attempts in the last 24 hours</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription className="flex items-center gap-1">
              <Lock className="h-4 w-4 text-red-500" /> Locked Accounts
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-red-500">{stats?.lockedAccountsCount ?? 0}</div>
            <p className="text-xs text-muted-foreground mt-1">Accounts currently locked due to failed attempts</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription className="flex items-center gap-1">
              <Globe className="h-4 w-4" /> Top Offending IPs
            </CardDescription>
          </CardHeader>
          <CardContent>
            {stats?.topIps && stats.topIps.length > 0 ? (
              <div className="space-y-1">
                {stats.topIps.slice(0, 3).map((ip) => (
                  <div key={ip.ip} className="flex justify-between text-sm">
                    <span className="font-mono text-xs truncate max-w-[160px]">{ip.ip}</span>
                    <Badge variant="secondary">{ip.count}</Badge>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No failed attempts in 24h</p>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="flex items-center gap-2 max-w-sm">
        <Search className="h-4 w-4 text-muted-foreground" />
        <Input
          placeholder="Filter by email..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="h-9"
        />
      </div>

      <Tabs defaultValue="locked" className="w-full">
        <TabsList>
          <TabsTrigger value="locked" className="flex items-center gap-1">
            <Lock className="h-3.5 w-3.5" /> Locked Accounts
            {locked.length > 0 && (
              <Badge variant="destructive" className="ml-1 text-xs px-1.5 py-0">
                {locked.length}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="history" className="flex items-center gap-1">
            <Clock className="h-3.5 w-3.5" /> Failed Login History
          </TabsTrigger>
          <TabsTrigger value="ips" className="flex items-center gap-1">
            <Globe className="h-3.5 w-3.5" /> Top IPs (24h)
          </TabsTrigger>
        </TabsList>

        <TabsContent value="locked" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Users className="h-4 w-4" /> Currently Locked Accounts
              </CardTitle>
              <CardDescription>
                Accounts locked after exceeding the failed login threshold (10 attempts in 30 minutes)
              </CardDescription>
            </CardHeader>
            <CardContent>
              {filteredLocked.length === 0 ? (
                <div className="text-center py-12">
                  <Unlock className="h-12 w-12 mx-auto text-muted-foreground/30 mb-3" />
                  <p className="text-muted-foreground">No accounts are currently locked</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Accounts are automatically locked after 10 failed login attempts
                  </p>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Email</TableHead>
                      <TableHead>Failed Attempts</TableHead>
                      <TableHead>Locked Until</TableHead>
                      <TableHead>Time Remaining</TableHead>
                      <TableHead>Last Failed IP</TableHead>
                      <TableHead>Last Failed At</TableHead>
                      <TableHead className="text-right">Action</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredLocked.map((account) => (
                      <TableRow key={account.id}>
                        <TableCell className="font-mono text-sm">{account.email || "\u2014"}</TableCell>
                        <TableCell>
                          <Badge variant="destructive">{account.failedLoginCount}</Badge>
                        </TableCell>
                        <TableCell className="text-sm">{formatDate(account.lockedUntil)}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="font-mono">
                            {timeRemaining(account.lockedUntil)}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs">{account.lastFailedIp || "\u2014"}</TableCell>
                        <TableCell className="text-sm">{formatDate(account.lastFailedAt)}</TableCell>
                        <TableCell className="text-right">
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={unlockMutation.isPending}
                            onClick={() => unlockMutation.mutate(account.id)}
                            className="hover:bg-green-50 hover:text-green-700 hover:border-green-300 transition-colors"
                          >
                            {unlockMutation.isPending ? (
                              <Loader2 className="h-3.5 w-3.5 animate-spin" />
                            ) : (
                              <Unlock className="h-3.5 w-3.5 mr-1" />
                            )}
                            Unlock
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="history" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <AlertTriangle className="h-4 w-4" /> Failed Login Attempts
              </CardTitle>
              <CardDescription>
                Showing {filteredHistory.length} of {history?.total ?? 0} total failed attempts
              </CardDescription>
            </CardHeader>
            <CardContent>
              {historyQuery.isPending ? (
                <div className="space-y-3">
                  {[1, 2, 3, 4, 5].map((i) => (
                    <Skeleton key={i} className="h-10 w-full" />
                  ))}
                </div>
              ) : filteredHistory.length === 0 ? (
                <div className="text-center py-12">
                  <ShieldAlert className="h-12 w-12 mx-auto text-muted-foreground/30 mb-3" />
                  <p className="text-muted-foreground">No failed login attempts recorded</p>
                </div>
              ) : (
                <>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Email</TableHead>
                        <TableHead>IP Address</TableHead>
                        <TableHead>Reason</TableHead>
                        <TableHead>Attempted At</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {filteredHistory.map((attempt) => (
                        <TableRow key={attempt.id}>
                          <TableCell className="font-mono text-sm">{attempt.email}</TableCell>
                          <TableCell className="font-mono text-xs">{attempt.ipAddress}</TableCell>
                          <TableCell>
                            <Badge variant="secondary" className="text-xs">
                              {attempt.reason}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-sm">{formatDate(attempt.attemptedAt)}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                  <div className="flex items-center justify-between mt-4">
                    <p className="text-xs text-muted-foreground">
                      Page {historyPage + 1} of {Math.max(1, Math.ceil((history?.total ?? 0) / pageSize))}
                    </p>
                    <div className="flex gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={historyPage === 0}
                        onClick={() => setHistoryPage((p) => Math.max(0, p - 1))}
                      >
                        <ChevronLeft className="h-4 w-4" /> Prev
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={(historyPage + 1) * pageSize >= (history?.total ?? 0)}
                        onClick={() => setHistoryPage((p) => p + 1)}
                      >
                        Next <ChevronRight className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="ips" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Globe className="h-4 w-4" /> Top Offending IP Addresses (24h)
              </CardTitle>
              <CardDescription>IP addresses with the most failed login attempts in the last 24 hours</CardDescription>
            </CardHeader>
            <CardContent>
              {!stats?.topIps || stats.topIps.length === 0 ? (
                <div className="text-center py-12">
                  <Globe className="h-12 w-12 mx-auto text-muted-foreground/30 mb-3" />
                  <p className="text-muted-foreground">No suspicious IP activity in the last 24 hours</p>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>IP Address</TableHead>
                      <TableHead>Failed Attempts</TableHead>
                      <TableHead>Risk Level</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {stats.topIps.map((ip) => (
                      <TableRow key={ip.ip}>
                        <TableCell className="font-mono">{ip.ip}</TableCell>
                        <TableCell>
                          <Badge variant={ip.count >= 10 ? "destructive" : "secondary"}>{ip.count}</Badge>
                        </TableCell>
                        <TableCell>
                          {ip.count >= 20 ? (
                            <Badge variant="destructive">Critical</Badge>
                          ) : ip.count >= 10 ? (
                            <Badge className="bg-orange-500 text-white">High</Badge>
                          ) : ip.count >= 5 ? (
                            <Badge className="bg-yellow-500 text-white">Medium</Badge>
                          ) : (
                            <Badge variant="secondary">Low</Badge>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
