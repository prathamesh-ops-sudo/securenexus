import { useState, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import {
  Users,
  Shield,
  UserPlus,
  Mail,
  Loader2,
  MoreHorizontal,
  UserX,
  UserCheck,
  Trash2,
  ScrollText,
  Crown,
  ShieldCheck,
  Eye,
  AlertTriangle,
  Globe,
  Key,
  Lock,
  Fingerprint,
  Network,
  Plus,
  CheckCircle2,
  XCircle,
  Clock,
  Copy,
  RefreshCw,
} from "lucide-react";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogClose } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Skeleton } from "@/components/ui/skeleton";
import { Label } from "@/components/ui/label";
import { apiRequest, queryClient } from "@/lib/queryClient";
import {
  formatDateShort as formatDate,
  formatDateTime,
  SUPPORTED_LOCALES,
  COMMON_TIMEZONES,
  setLocale,
  setTimezone,
} from "@/lib/i18n";
import { useToast } from "@/hooks/use-toast";

const ROLE_COLORS: Record<string, string> = {
  owner: "border-red-500/30 text-red-400",
  admin: "border-orange-500/30 text-orange-400",
  analyst: "border-blue-500/30 text-blue-400",
  read_only: "border-gray-500/30 text-gray-400",
};

const ROLE_ICONS: Record<string, typeof Crown> = {
  owner: Crown,
  admin: ShieldCheck,
  analyst: Shield,
  read_only: Eye,
};

const STATUS_COLORS: Record<string, string> = {
  active: "border-green-500/30 text-green-400",
  suspended: "border-red-500/30 text-red-400",
  invited: "border-yellow-500/30 text-yellow-400",
};

const ASSIGNABLE_ROLES = ["admin", "analyst", "read_only"];

function useOrgContext() {
  const ensureOrg = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/auth/ensure-org");
      return res.json();
    },
    onSuccess: (data) => {
      queryClient.setQueryData(["org-context"], data);
    },
  });

  const { data, isLoading: _queryLoading } = useQuery<any>({
    queryKey: ["org-context"],
    enabled: false,
  });

  useEffect(() => {
    if (!data && !ensureOrg.isPending && !ensureOrg.isSuccess) {
      ensureOrg.mutate();
    }
  }, []);

  const orgData = data || ensureOrg.data;

  return {
    orgId: orgData?.membership?.orgId || orgData?.organization?.id,
    orgRole: orgData?.membership?.role,
    organization: orgData?.organization,
    isLoading: ensureOrg.isPending || (!orgData && !ensureOrg.isError),
  };
}

function MembersTab({ orgId, orgRole }: { orgId: string; orgRole: string }) {
  const { toast } = useToast();
  const isAdmin = orgRole === "owner" || orgRole === "admin";
  const [roleDialogOpen, setRoleDialogOpen] = useState(false);
  const [selectedMember, setSelectedMember] = useState<any>(null);
  const [newRole, setNewRole] = useState("");

  const {
    data: members,
    isLoading,
    isError: membersError,
    refetch: refetchMembers,
  } = useQuery<any[]>({
    queryKey: ["/api/orgs", orgId, "members"],
    enabled: !!orgId,
  });

  const changeRole = useMutation({
    mutationFn: async ({ memberId, role }: { memberId: string; role: string }) => {
      await apiRequest("PATCH", `/api/orgs/${orgId}/members/${memberId}/role`, { role });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/orgs", orgId, "members"] });
      setRoleDialogOpen(false);
      setSelectedMember(null);
      toast({ title: "Role updated", description: "Member role has been changed successfully." });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to update role", description: error.message, variant: "destructive" });
    },
  });

  const suspendMember = useMutation({
    mutationFn: async (memberId: string) => {
      await apiRequest("POST", `/api/orgs/${orgId}/members/${memberId}/suspend`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/orgs", orgId, "members"] });
      toast({ title: "Member suspended", description: "Member has been suspended." });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to suspend member", description: error.message, variant: "destructive" });
    },
  });

  const activateMember = useMutation({
    mutationFn: async (memberId: string) => {
      await apiRequest("POST", `/api/orgs/${orgId}/members/${memberId}/activate`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/orgs", orgId, "members"] });
      toast({ title: "Member activated", description: "Member has been reactivated." });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to activate member", description: error.message, variant: "destructive" });
    },
  });

  const removeMember = useMutation({
    mutationFn: async (memberId: string) => {
      await apiRequest("DELETE", `/api/orgs/${orgId}/members/${memberId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/orgs", orgId, "members"] });
      toast({ title: "Member removed", description: "Member has been removed from the organization." });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to remove member", description: error.message, variant: "destructive" });
    },
  });

  const openRoleDialog = (member: any) => {
    setSelectedMember(member);
    setNewRole(member.role);
    setRoleDialogOpen(true);
  };

  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-4 space-y-3">
          {[1, 2, 3].map((i) => (
            <div key={i} className="flex items-center gap-4">
              <Skeleton className="h-8 w-8 rounded-full" />
              <Skeleton className="h-4 flex-1" />
              <Skeleton className="h-6 w-16" />
              <Skeleton className="h-6 w-16" />
            </div>
          ))}
        </CardContent>
      </Card>
    );
  }

  if (membersError) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center" role="alert">
        <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <p className="text-sm font-medium">Failed to load team members</p>
        <p className="text-xs text-muted-foreground mt-1">An error occurred while fetching data.</p>
        <Button variant="outline" size="sm" className="mt-3" onClick={() => refetchMembers()}>
          Try Again
        </Button>
      </div>
    );
  }

  return (
    <>
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2 flex-wrap">
            <Users className="h-4 w-4 text-muted-foreground" />
            Organization Members
          </CardTitle>
          <Badge variant="secondary" className="text-[10px]" data-testid="badge-member-count">
            {members?.length || 0} members
          </Badge>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto border rounded-md">
            <Table data-testid="table-members">
              <TableHeader>
                <TableRow>
                  <TableHead className="text-xs">User</TableHead>
                  <TableHead className="text-xs">Role</TableHead>
                  <TableHead className="text-xs">Status</TableHead>
                  <TableHead className="text-xs">Joined</TableHead>
                  {isAdmin && <TableHead className="text-xs">Actions</TableHead>}
                </TableRow>
              </TableHeader>
              <TableBody>
                {members && members.length > 0 ? (
                  members.map((member: any) => {
                    const RoleIcon = ROLE_ICONS[member.role] || Shield;
                    return (
                      <TableRow key={member.id} data-testid={`row-member-${member.id}`}>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <div className="flex items-center justify-center h-8 w-8 rounded-full bg-muted text-xs font-medium flex-shrink-0">
                              {(member.user?.firstName?.[0] || member.email?.[0] || "U").toUpperCase()}
                            </div>
                            <div>
                              <div className="text-sm font-medium" data-testid={`text-member-name-${member.id}`}>
                                {member.user?.firstName && member.user?.lastName
                                  ? `${member.user.firstName} ${member.user.lastName}`
                                  : member.email || "Unknown"}
                              </div>
                              {member.user?.email && (
                                <div
                                  className="text-xs text-muted-foreground"
                                  data-testid={`text-member-email-${member.id}`}
                                >
                                  {member.user.email}
                                </div>
                              )}
                              {!member.user?.email && member.email && (
                                <div
                                  className="text-xs text-muted-foreground"
                                  data-testid={`text-member-email-${member.id}`}
                                >
                                  {member.email}
                                </div>
                              )}
                            </div>
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={`no-default-hover-elevate no-default-active-elevate text-[10px] ${ROLE_COLORS[member.role] || ""}`}
                            data-testid={`badge-role-${member.id}`}
                          >
                            <RoleIcon className="h-2.5 w-2.5 mr-0.5" />
                            {member.role}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={`no-default-hover-elevate no-default-active-elevate text-[10px] ${STATUS_COLORS[member.status] || ""}`}
                            data-testid={`badge-status-${member.id}`}
                          >
                            {member.status}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <span className="text-xs text-muted-foreground" data-testid={`text-joined-${member.id}`}>
                            {formatDate(member.createdAt || member.joinedAt)}
                          </span>
                        </TableCell>
                        {isAdmin && (
                          <TableCell>
                            {member.role !== "owner" && (
                              <DropdownMenu>
                                <DropdownMenuTrigger asChild>
                                  <Button size="icon" variant="ghost" data-testid={`button-actions-${member.id}`}>
                                    <MoreHorizontal className="h-4 w-4" />
                                  </Button>
                                </DropdownMenuTrigger>
                                <DropdownMenuContent align="end">
                                  <DropdownMenuItem
                                    onClick={() => openRoleDialog(member)}
                                    data-testid={`action-change-role-${member.id}`}
                                  >
                                    <Shield className="h-4 w-4 mr-2" />
                                    Change Role
                                  </DropdownMenuItem>
                                  {member.status === "active" ? (
                                    <DropdownMenuItem
                                      onClick={() => suspendMember.mutate(member.id)}
                                      data-testid={`action-suspend-${member.id}`}
                                    >
                                      <UserX className="h-4 w-4 mr-2" />
                                      Suspend
                                    </DropdownMenuItem>
                                  ) : member.status === "suspended" ? (
                                    <DropdownMenuItem
                                      onClick={() => activateMember.mutate(member.id)}
                                      data-testid={`action-activate-${member.id}`}
                                    >
                                      <UserCheck className="h-4 w-4 mr-2" />
                                      Activate
                                    </DropdownMenuItem>
                                  ) : null}
                                  <DropdownMenuItem
                                    onClick={() => removeMember.mutate(member.id)}
                                    className="text-red-400"
                                    data-testid={`action-remove-${member.id}`}
                                  >
                                    <Trash2 className="h-4 w-4 mr-2" />
                                    Remove
                                  </DropdownMenuItem>
                                </DropdownMenuContent>
                              </DropdownMenu>
                            )}
                          </TableCell>
                        )}
                      </TableRow>
                    );
                  })
                ) : (
                  <TableRow>
                    <TableCell colSpan={isAdmin ? 5 : 4} className="text-center text-sm text-muted-foreground py-8">
                      No members found
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      <Dialog open={roleDialogOpen} onOpenChange={setRoleDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Change Member Role</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="text-sm text-muted-foreground">
              Changing role for{" "}
              <span className="font-medium text-foreground">
                {selectedMember?.user?.email || selectedMember?.email || "member"}
              </span>
            </div>
            <div className="space-y-1.5">
              <label className="text-xs text-muted-foreground">New Role</label>
              <Select value={newRole} onValueChange={setNewRole}>
                <SelectTrigger data-testid="select-new-role">
                  <SelectValue placeholder="Select role" />
                </SelectTrigger>
                <SelectContent>
                  {ASSIGNABLE_ROLES.map((role) => (
                    <SelectItem key={role} value={role}>
                      {role.replace("_", " ")}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline" data-testid="button-cancel-role-change">
                Cancel
              </Button>
            </DialogClose>
            <Button
              onClick={() => selectedMember && changeRole.mutate({ memberId: selectedMember.id, role: newRole })}
              disabled={!newRole || changeRole.isPending}
              data-testid="button-confirm-role-change"
            >
              {changeRole.isPending ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Shield className="h-4 w-4 mr-2" />
              )}
              Update Role
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

function InvitationsTab({ orgId, orgRole }: { orgId: string; orgRole: string }) {
  const { toast } = useToast();
  const isAdmin = orgRole === "owner" || orgRole === "admin";
  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("analyst");

  const { data: invitations, isLoading } = useQuery<any[]>({
    queryKey: ["/api/orgs", orgId, "invitations"],
    enabled: !!orgId,
  });

  const createInvitation = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", `/api/orgs/${orgId}/invitations`, {
        email: inviteEmail,
        role: inviteRole,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/orgs", orgId, "invitations"] });
      setInviteOpen(false);
      setInviteEmail("");
      setInviteRole("analyst");
      toast({ title: "Invitation sent", description: "Team member has been invited successfully." });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to send invitation", description: error.message, variant: "destructive" });
    },
  });

  const cancelInvitation = useMutation({
    mutationFn: async (invitationId: string) => {
      await apiRequest("DELETE", `/api/orgs/${orgId}/invitations/${invitationId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/orgs", orgId, "invitations"] });
      toast({ title: "Invitation cancelled", description: "The invitation has been revoked." });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to cancel invitation", description: error.message, variant: "destructive" });
    },
  });

  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-4 space-y-3">
          {[1, 2].map((i) => (
            <div key={i} className="flex items-center gap-4">
              <Skeleton className="h-4 flex-1" />
              <Skeleton className="h-6 w-16" />
              <Skeleton className="h-6 w-20" />
            </div>
          ))}
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-3">
        <CardTitle className="text-sm font-semibold flex items-center gap-2 flex-wrap">
          <Mail className="h-4 w-4 text-muted-foreground" />
          Pending Invitations
        </CardTitle>
        {isAdmin && (
          <Button size="sm" onClick={() => setInviteOpen(true)} data-testid="button-invite-member">
            <UserPlus className="h-4 w-4 mr-1" />
            Invite Member
          </Button>
        )}
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto border rounded-md">
          <Table data-testid="table-invitations">
            <TableHeader>
              <TableRow>
                <TableHead className="text-xs">Email</TableHead>
                <TableHead className="text-xs">Role</TableHead>
                <TableHead className="text-xs">Invited By</TableHead>
                <TableHead className="text-xs">Expires</TableHead>
                {isAdmin && <TableHead className="text-xs">Actions</TableHead>}
              </TableRow>
            </TableHeader>
            <TableBody>
              {invitations && invitations.length > 0 ? (
                invitations.map((inv: any) => (
                  <TableRow key={inv.id} data-testid={`row-invitation-${inv.id}`}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Mail className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0" />
                        <span className="text-sm" data-testid={`text-invite-email-${inv.id}`}>
                          {inv.email}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant="outline"
                        className={`no-default-hover-elevate no-default-active-elevate text-[10px] ${ROLE_COLORS[inv.role] || ""}`}
                        data-testid={`badge-invite-role-${inv.id}`}
                      >
                        {inv.role}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs text-muted-foreground" data-testid={`text-invited-by-${inv.id}`}>
                        {inv.invitedBy || inv.invitedByEmail || "System"}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs text-muted-foreground" data-testid={`text-invite-expires-${inv.id}`}>
                        {formatDate(inv.expiresAt)}
                      </span>
                    </TableCell>
                    {isAdmin && (
                      <TableCell>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => cancelInvitation.mutate(inv.id)}
                          disabled={cancelInvitation.isPending}
                          data-testid={`button-cancel-invite-${inv.id}`}
                        >
                          {cancelInvitation.isPending && cancelInvitation.variables === inv.id ? (
                            <Loader2 className="h-3.5 w-3.5 animate-spin" />
                          ) : (
                            <Trash2 className="h-3.5 w-3.5" />
                          )}
                        </Button>
                      </TableCell>
                    )}
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell colSpan={isAdmin ? 5 : 4} className="text-center text-sm text-muted-foreground py-8">
                    No pending invitations
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      </CardContent>

      <Dialog open={inviteOpen} onOpenChange={setInviteOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Invite Team Member</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <label className="text-xs text-muted-foreground">Email Address</label>
              <Input
                type="email"
                placeholder="colleague@example.com"
                value={inviteEmail}
                onChange={(e) => setInviteEmail(e.target.value)}
                data-testid="input-invite-email"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs text-muted-foreground">Role</label>
              <Select value={inviteRole} onValueChange={setInviteRole}>
                <SelectTrigger data-testid="select-invite-role">
                  <SelectValue placeholder="Select role" />
                </SelectTrigger>
                <SelectContent>
                  {ASSIGNABLE_ROLES.map((role) => (
                    <SelectItem key={role} value={role}>
                      {role.replace("_", " ")}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline" data-testid="button-cancel-invite">
                Cancel
              </Button>
            </DialogClose>
            <Button
              onClick={() => createInvitation.mutate()}
              disabled={!inviteEmail || createInvitation.isPending}
              data-testid="button-send-invite"
            >
              {createInvitation.isPending ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <UserPlus className="h-4 w-4 mr-2" />
              )}
              Send Invitation
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}

function SecurityTab({ orgId, orgRole }: { orgId: string; orgRole: string }) {
  const { toast } = useToast();
  const isOwner = orgRole === "owner";
  const [activeSection, setActiveSection] = useState<string>("policies");

  const { data: securityPolicy, isLoading: policyLoading } = useQuery<any>({
    queryKey: ["/api/orgs", orgId, "security-policy"],
    queryFn: async () => {
      try {
        const res = await apiRequest("GET", `/api/orgs/${orgId}/security-policy`);
        return res.json();
      } catch {
        return null;
      }
    },
    enabled: !!orgId,
  });

  const {
    data: domains,
    isLoading: domainsLoading,
    refetch: refetchDomains,
  } = useQuery<any[]>({
    queryKey: ["/api/orgs", orgId, "domains"],
    queryFn: async () => {
      try {
        const res = await apiRequest("GET", `/api/orgs/${orgId}/domains`);
        return res.json();
      } catch {
        return [];
      }
    },
    enabled: !!orgId,
  });

  const {
    data: ssoConfig,
    isLoading: ssoLoading,
    refetch: refetchSso,
  } = useQuery<any>({
    queryKey: ["/api/orgs", orgId, "sso"],
    queryFn: async () => {
      try {
        const res = await apiRequest("GET", `/api/orgs/${orgId}/sso`);
        return res.json();
      } catch {
        return null;
      }
    },
    enabled: !!orgId,
  });

  const {
    data: scimConfig,
    isLoading: scimLoading,
    refetch: refetchScim,
  } = useQuery<any>({
    queryKey: ["/api/orgs", orgId, "scim"],
    queryFn: async () => {
      try {
        const res = await apiRequest("GET", `/api/orgs/${orgId}/scim`);
        return res.json();
      } catch {
        return null;
      }
    },
    enabled: !!orgId,
  });

  const updatePolicy = useMutation({
    mutationFn: async (data: Record<string, unknown>) => {
      const res = await apiRequest("PUT", `/api/orgs/${orgId}/security-policy`, data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/orgs", orgId, "security-policy"] });
      toast({ title: "Security policy updated" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to update policy", description: error.message, variant: "destructive" });
    },
  });

  const addDomain = useMutation({
    mutationFn: async (data: { domain: string; verificationMethod: string }) => {
      const res = await apiRequest("POST", `/api/orgs/${orgId}/domains`, data);
      return res.json();
    },
    onSuccess: () => {
      refetchDomains();
      toast({ title: "Domain added" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to add domain", description: error.message, variant: "destructive" });
    },
  });

  const verifyDomain = useMutation({
    mutationFn: async (domainId: string) => {
      const res = await apiRequest("POST", `/api/orgs/${orgId}/domains/${domainId}/verify`);
      return res.json();
    },
    onSuccess: () => {
      refetchDomains();
      toast({ title: "Domain verification initiated" });
    },
    onError: (error: Error) => {
      toast({ title: "Verification failed", description: error.message, variant: "destructive" });
    },
  });

  const deleteDomain = useMutation({
    mutationFn: async (domainId: string) => {
      await apiRequest("DELETE", `/api/orgs/${orgId}/domains/${domainId}`);
    },
    onSuccess: () => {
      refetchDomains();
      toast({ title: "Domain removed" });
    },
  });

  const updateSso = useMutation({
    mutationFn: async (data: Record<string, unknown>) => {
      const res = await apiRequest("PUT", `/api/orgs/${orgId}/sso`, data);
      return res.json();
    },
    onSuccess: () => {
      refetchSso();
      toast({ title: "SSO configuration updated" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to update SSO", description: error.message, variant: "destructive" });
    },
  });

  const updateScim = useMutation({
    mutationFn: async (data: Record<string, unknown>) => {
      const res = await apiRequest("PUT", `/api/orgs/${orgId}/scim`, data);
      return res.json();
    },
    onSuccess: () => {
      refetchScim();
      toast({ title: "SCIM configuration updated" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to update SCIM", description: error.message, variant: "destructive" });
    },
  });

  const generateScimToken = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/orgs/${orgId}/scim/generate-token`);
      return res.json();
    },
    onSuccess: (data) => {
      refetchScim();
      if (data.token) {
        navigator.clipboard
          .writeText(data.token)
          .then(() => {
            toast({ title: "SCIM token generated and copied to clipboard" });
          })
          .catch(() => {
            toast({ title: "SCIM token generated", description: "Token: " + data.token.substring(0, 12) + "..." });
          });
      }
    },
    onError: (error: Error) => {
      toast({ title: "Failed to generate token", description: error.message, variant: "destructive" });
    },
  });

  const [newDomain, setNewDomain] = useState("");
  const [newDomainMethod, setNewDomainMethod] = useState("dns_txt");
  const [ipInput, setIpInput] = useState("");
  const [selectedLocale, setSelectedLocale] = useState(securityPolicy?.locale || "en-US");
  const [selectedTimezone, setSelectedTimezone] = useState(securityPolicy?.timezone || "UTC");

  const updateLocaleTimezone = useMutation({
    mutationFn: async (data: { locale?: string; timezone?: string }) => {
      const res = await apiRequest("PUT", `/api/orgs/${orgId}/security-policy`, data);
      return res.json();
    },
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ["/api/orgs", orgId, "security-policy"] });
      if (variables.locale) setLocale(variables.locale);
      if (variables.timezone) setTimezone(variables.timezone);
      toast({ title: "Locale & timezone updated" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to update", description: error.message, variant: "destructive" });
    },
  });

  if (policyLoading || domainsLoading || ssoLoading || scimLoading) {
    return (
      <Card>
        <CardContent className="p-6 space-y-4">
          {[1, 2, 3].map((i) => (
            <div key={i} className="space-y-2">
              <Skeleton className="h-4 w-32" />
              <Skeleton className="h-8 w-full" />
            </div>
          ))}
        </CardContent>
      </Card>
    );
  }

  if (!isOwner) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center justify-center py-12 gap-3">
          <Lock className="h-8 w-8 text-muted-foreground" />
          <div className="text-sm text-muted-foreground">Only organization owners can manage security settings.</div>
        </CardContent>
      </Card>
    );
  }

  const SECTIONS = [
    { key: "policies", label: "MFA & Session", icon: Fingerprint },
    { key: "domains", label: "Domains", icon: Globe },
    { key: "sso", label: "SSO", icon: Key },
    { key: "scim", label: "SCIM", icon: Network },
    { key: "ip", label: "IP Allowlist", icon: Shield },
    { key: "locale", label: "Locale & Timezone", icon: Globe },
  ];

  const currentIps: string[] = securityPolicy?.ipAllowlistCidrs || [];

  return (
    <div className="space-y-4">
      <div className="flex gap-1 flex-wrap">
        {SECTIONS.map((sec) => {
          const Icon = sec.icon;
          return (
            <Button
              key={sec.key}
              variant={activeSection === sec.key ? "default" : "outline"}
              size="sm"
              onClick={() => setActiveSection(sec.key)}
              data-testid={`security-section-${sec.key}`}
            >
              <Icon className="h-3.5 w-3.5 mr-1.5" />
              {sec.label}
            </Button>
          );
        })}
      </div>

      {activeSection === "policies" && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Fingerprint className="h-4 w-4 text-primary" />
              MFA, Session & Password Policies
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="flex items-center justify-between p-3 border rounded-md">
                <div>
                  <div className="text-sm font-medium">Require MFA</div>
                  <div className="text-xs text-muted-foreground">
                    All members must enable multi-factor authentication
                  </div>
                </div>
                <Switch
                  checked={securityPolicy?.mfaRequired || false}
                  onCheckedChange={(checked) => updatePolicy.mutate({ mfaRequired: checked })}
                  data-testid="switch-mfa-required"
                />
              </div>
              <div className="flex items-center justify-between p-3 border rounded-md">
                <div>
                  <div className="text-sm font-medium">Device Trust</div>
                  <div className="text-xs text-muted-foreground">Require trusted device verification</div>
                </div>
                <Switch
                  checked={securityPolicy?.deviceTrustRequired || false}
                  onCheckedChange={(checked) => updatePolicy.mutate({ deviceTrustRequired: checked })}
                  data-testid="switch-device-trust"
                />
              </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="space-y-1">
                <label className="text-xs text-muted-foreground">Session Timeout (minutes)</label>
                <Input
                  type="number"
                  defaultValue={securityPolicy?.sessionTimeoutMinutes || 480}
                  onBlur={(e) => updatePolicy.mutate({ sessionTimeoutMinutes: parseInt(e.target.value, 10) })}
                  className="h-8 text-sm"
                  data-testid="input-session-timeout"
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs text-muted-foreground">Max Concurrent Sessions</label>
                <Input
                  type="number"
                  defaultValue={securityPolicy?.maxConcurrentSessions || 5}
                  onBlur={(e) => updatePolicy.mutate({ maxConcurrentSessions: parseInt(e.target.value, 10) })}
                  className="h-8 text-sm"
                  data-testid="input-max-sessions"
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs text-muted-foreground">Password Expiry (days)</label>
                <Input
                  type="number"
                  defaultValue={securityPolicy?.passwordExpiryDays || 90}
                  onBlur={(e) => updatePolicy.mutate({ passwordExpiryDays: parseInt(e.target.value, 10) })}
                  className="h-8 text-sm"
                  data-testid="input-password-expiry"
                />
              </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="space-y-1">
                <label className="text-xs text-muted-foreground">Min Password Length</label>
                <Input
                  type="number"
                  defaultValue={securityPolicy?.passwordMinLength || 12}
                  onBlur={(e) => updatePolicy.mutate({ passwordMinLength: parseInt(e.target.value, 10) })}
                  className="h-8 text-sm"
                  data-testid="input-password-min-length"
                />
              </div>
              <div className="space-y-2 p-3 border rounded-md">
                <div className="text-xs text-muted-foreground">Password Requirements</div>
                <div className="flex flex-wrap gap-2">
                  <div className="flex items-center gap-1.5">
                    <Switch
                      checked={securityPolicy?.passwordRequireUppercase !== false}
                      onCheckedChange={(checked) => updatePolicy.mutate({ passwordRequireUppercase: checked })}
                    />
                    <span className="text-xs">Uppercase</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Switch
                      checked={securityPolicy?.passwordRequireNumber !== false}
                      onCheckedChange={(checked) => updatePolicy.mutate({ passwordRequireNumber: checked })}
                    />
                    <span className="text-xs">Number</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Switch
                      checked={securityPolicy?.passwordRequireSpecial !== false}
                      onCheckedChange={(checked) => updatePolicy.mutate({ passwordRequireSpecial: checked })}
                    />
                    <span className="text-xs">Special char</span>
                  </div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {activeSection === "domains" && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Globe className="h-4 w-4 text-primary" />
              Domain Verification
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex gap-2">
              <Input
                placeholder="example.com"
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
                className="flex-1 h-8 text-sm"
                data-testid="input-new-domain"
              />
              <Select value={newDomainMethod} onValueChange={setNewDomainMethod}>
                <SelectTrigger className="w-32 h-8 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="dns_txt">DNS TXT</SelectItem>
                  <SelectItem value="dns_cname">DNS CNAME</SelectItem>
                  <SelectItem value="meta_tag">Meta Tag</SelectItem>
                </SelectContent>
              </Select>
              <Button
                size="sm"
                className="h-8"
                disabled={!newDomain.trim() || addDomain.isPending}
                onClick={() => {
                  addDomain.mutate({ domain: newDomain.trim(), verificationMethod: newDomainMethod });
                  setNewDomain("");
                }}
                data-testid="button-add-domain"
              >
                <Plus className="h-3.5 w-3.5 mr-1" />
                Add
              </Button>
            </div>
            {domains && domains.length > 0 ? (
              <div className="border rounded-md overflow-hidden">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="text-xs">Domain</TableHead>
                      <TableHead className="text-xs">Method</TableHead>
                      <TableHead className="text-xs">Status</TableHead>
                      <TableHead className="text-xs">Token</TableHead>
                      <TableHead className="text-xs">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {domains.map((d: any) => (
                      <TableRow key={d.id}>
                        <TableCell className="text-sm font-medium">{d.domain}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="text-[10px]">
                            {d.verificationMethod}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={`text-[10px] ${
                              d.status === "verified"
                                ? "border-green-500/30 text-green-400"
                                : d.status === "failed"
                                  ? "border-red-500/30 text-red-400"
                                  : "border-yellow-500/30 text-yellow-400"
                            }`}
                          >
                            {d.status === "verified" && <CheckCircle2 className="h-2.5 w-2.5 mr-0.5" />}
                            {d.status === "failed" && <XCircle className="h-2.5 w-2.5 mr-0.5" />}
                            {d.status === "pending" && <Clock className="h-2.5 w-2.5 mr-0.5" />}
                            {d.status}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <button
                            onClick={() => {
                              navigator.clipboard.writeText(d.verificationToken || "");
                              toast({ title: "Token copied" });
                            }}
                            className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1"
                          >
                            <Copy className="h-3 w-3" />
                            {(d.verificationToken || "").substring(0, 16)}...
                          </button>
                        </TableCell>
                        <TableCell>
                          <div className="flex gap-1">
                            {d.status !== "verified" && (
                              <Button
                                size="sm"
                                variant="ghost"
                                className="h-7"
                                onClick={() => verifyDomain.mutate(d.id)}
                                disabled={verifyDomain.isPending}
                              >
                                <RefreshCw className="h-3 w-3" />
                              </Button>
                            )}
                            <Button
                              size="sm"
                              variant="ghost"
                              className="h-7 text-destructive"
                              onClick={() => deleteDomain.mutate(d.id)}
                            >
                              <Trash2 className="h-3 w-3" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            ) : (
              <div className="text-center py-8 text-sm text-muted-foreground">
                No domains configured. Add a domain to enable email-based auto-provisioning.
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {activeSection === "sso" && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Key className="h-4 w-4 text-primary" />
              Single Sign-On (SSO)
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="flex items-center justify-between p-3 border rounded-md">
                <div>
                  <div className="text-sm font-medium">Enable SSO</div>
                  <div className="text-xs text-muted-foreground">Allow SSO-based authentication</div>
                </div>
                <Switch
                  checked={ssoConfig?.enabled || false}
                  onCheckedChange={(checked) => updateSso.mutate({ enabled: checked })}
                  data-testid="switch-sso-enabled"
                />
              </div>
              <div className="flex items-center justify-between p-3 border rounded-md">
                <div>
                  <div className="text-sm font-medium">Enforce SSO</div>
                  <div className="text-xs text-muted-foreground">Require SSO for all members (no password login)</div>
                </div>
                <Switch
                  checked={ssoConfig?.enforced || false}
                  onCheckedChange={(checked) => updateSso.mutate({ enforced: checked })}
                  data-testid="switch-sso-enforced"
                />
              </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="space-y-1">
                <label className="text-xs text-muted-foreground">Provider Type</label>
                <Select
                  value={ssoConfig?.providerType || "saml"}
                  onValueChange={(v) => updateSso.mutate({ providerType: v })}
                >
                  <SelectTrigger className="h-8 text-xs" data-testid="select-sso-provider">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="saml">SAML 2.0</SelectItem>
                    <SelectItem value="oidc">OpenID Connect</SelectItem>
                    <SelectItem value="google">Google Workspace</SelectItem>
                    <SelectItem value="github">GitHub</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <label className="text-xs text-muted-foreground">Default Role for SSO Users</label>
                <Select
                  value={ssoConfig?.defaultRole || "analyst"}
                  onValueChange={(v) => updateSso.mutate({ defaultRole: v })}
                >
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="admin">Admin</SelectItem>
                    <SelectItem value="analyst">Analyst</SelectItem>
                    <SelectItem value="read_only">Read Only</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            {(ssoConfig?.providerType === "saml" || !ssoConfig?.providerType) && (
              <div className="space-y-3">
                <div className="space-y-1">
                  <label className="text-xs text-muted-foreground">Metadata URL</label>
                  <Input
                    placeholder="https://idp.example.com/metadata.xml"
                    defaultValue={ssoConfig?.metadataUrl || ""}
                    onBlur={(e) => updateSso.mutate({ metadataUrl: e.target.value })}
                    className="h-8 text-sm"
                    data-testid="input-sso-metadata-url"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-xs text-muted-foreground">Entity ID</label>
                  <Input
                    placeholder="urn:example:sp"
                    defaultValue={ssoConfig?.entityId || ""}
                    onBlur={(e) => updateSso.mutate({ entityId: e.target.value })}
                    className="h-8 text-sm"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-xs text-muted-foreground">SSO URL</label>
                  <Input
                    placeholder="https://idp.example.com/sso"
                    defaultValue={ssoConfig?.ssoUrl || ""}
                    onBlur={(e) => updateSso.mutate({ ssoUrl: e.target.value })}
                    className="h-8 text-sm"
                  />
                </div>
              </div>
            )}
            {ssoConfig?.providerType === "oidc" && (
              <div className="space-y-3">
                <div className="space-y-1">
                  <label className="text-xs text-muted-foreground">Client ID</label>
                  <Input
                    defaultValue={ssoConfig?.clientId || ""}
                    onBlur={(e) => updateSso.mutate({ clientId: e.target.value })}
                    className="h-8 text-sm"
                  />
                </div>
              </div>
            )}
            <div className="flex items-center justify-between p-3 border rounded-md">
              <div>
                <div className="text-sm font-medium">Auto-Provision Users</div>
                <div className="text-xs text-muted-foreground">Automatically create accounts for SSO users</div>
              </div>
              <Switch
                checked={ssoConfig?.autoProvision !== false}
                onCheckedChange={(checked) => updateSso.mutate({ autoProvision: checked })}
              />
            </div>
          </CardContent>
        </Card>
      )}

      {activeSection === "scim" && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Network className="h-4 w-4 text-primary" />
              SCIM Provisioning
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between p-3 border rounded-md">
              <div>
                <div className="text-sm font-medium">Enable SCIM</div>
                <div className="text-xs text-muted-foreground">
                  Allow identity providers to manage users via SCIM 2.0
                </div>
              </div>
              <Switch
                checked={scimConfig?.enabled || false}
                onCheckedChange={(checked) => updateScim.mutate({ enabled: checked })}
                data-testid="switch-scim-enabled"
              />
            </div>
            {scimConfig?.enabled && (
              <>
                <div className="space-y-3">
                  <div className="space-y-1">
                    <label className="text-xs text-muted-foreground">SCIM Endpoint URL</label>
                    <div className="flex gap-2">
                      <Input
                        value={scimConfig?.endpointUrl || "Not configured"}
                        readOnly
                        className="h-8 text-sm bg-muted/50"
                      />
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-8"
                        onClick={() => {
                          navigator.clipboard.writeText(scimConfig?.endpointUrl || "");
                          toast({ title: "Endpoint URL copied" });
                        }}
                      >
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                  <div className="space-y-1">
                    <label className="text-xs text-muted-foreground">Bearer Token</label>
                    <div className="flex gap-2">
                      <Input
                        value={scimConfig?.bearerTokenPrefix ? `${scimConfig.bearerTokenPrefix}...` : "Not generated"}
                        readOnly
                        className="h-8 text-sm bg-muted/50"
                      />
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-8"
                        onClick={() => generateScimToken.mutate()}
                        disabled={generateScimToken.isPending}
                        data-testid="button-generate-scim-token"
                      >
                        {generateScimToken.isPending ? (
                          <Loader2 className="h-3 w-3 animate-spin" />
                        ) : (
                          <RefreshCw className="h-3 w-3" />
                        )}
                        <span className="ml-1 text-xs">Generate</span>
                      </Button>
                    </div>
                  </div>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <label className="text-xs text-muted-foreground">Default Role</label>
                    <Select
                      value={scimConfig?.defaultRole || "analyst"}
                      onValueChange={(v) => updateScim.mutate({ defaultRole: v })}
                    >
                      <SelectTrigger className="h-8 text-xs">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="admin">Admin</SelectItem>
                        <SelectItem value="analyst">Analyst</SelectItem>
                        <SelectItem value="read_only">Read Only</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="flex items-center justify-between p-3 border rounded-md">
                    <div>
                      <div className="text-xs font-medium">Auto-Deprovision</div>
                      <div className="text-[10px] text-muted-foreground">Remove users when deprovisioned in IdP</div>
                    </div>
                    <Switch
                      checked={scimConfig?.autoDeprovision !== false}
                      onCheckedChange={(checked) => updateScim.mutate({ autoDeprovision: checked })}
                    />
                  </div>
                </div>
                {scimConfig?.lastSyncAt && (
                  <div className="text-xs text-muted-foreground p-2 bg-muted/30 rounded-md">
                    Last sync: {formatDateTime(scimConfig.lastSyncAt)} — Status:{" "}
                    {scimConfig.lastSyncStatus || "unknown"} — Users: {scimConfig.lastSyncUserCount || 0}
                  </div>
                )}
              </>
            )}
          </CardContent>
        </Card>
      )}

      {activeSection === "ip" && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Shield className="h-4 w-4 text-primary" />
              IP Allowlist
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between p-3 border rounded-md">
              <div>
                <div className="text-sm font-medium">Enable IP Allowlist</div>
                <div className="text-xs text-muted-foreground">
                  Restrict access to specific IP ranges (CIDR notation)
                </div>
              </div>
              <Switch
                checked={securityPolicy?.ipAllowlistEnabled || false}
                onCheckedChange={(checked) => updatePolicy.mutate({ ipAllowlistEnabled: checked })}
                data-testid="switch-ip-allowlist"
              />
            </div>
            <div className="flex gap-2">
              <Input
                placeholder="10.0.0.0/8 or 192.168.1.0/24"
                value={ipInput}
                onChange={(e) => setIpInput(e.target.value)}
                className="flex-1 h-8 text-sm"
                data-testid="input-ip-cidr"
              />
              <Button
                size="sm"
                className="h-8"
                disabled={!ipInput.trim()}
                onClick={() => {
                  const updated = [...currentIps, ipInput.trim()];
                  updatePolicy.mutate({ ipAllowlistCidrs: updated });
                  setIpInput("");
                }}
                data-testid="button-add-ip"
              >
                <Plus className="h-3.5 w-3.5 mr-1" />
                Add
              </Button>
            </div>
            {currentIps.length > 0 ? (
              <div className="space-y-1">
                {currentIps.map((cidr, idx) => (
                  <div key={idx} className="flex items-center justify-between p-2 border rounded-md text-sm">
                    <code className="text-xs font-mono">{cidr}</code>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-6 text-destructive"
                      onClick={() => {
                        const updated = currentIps.filter((_, i) => i !== idx);
                        updatePolicy.mutate({ ipAllowlistCidrs: updated });
                      }}
                    >
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-6 text-sm text-muted-foreground">
                No IP ranges configured. All IPs are currently allowed.
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {activeSection === "locale" && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Globe className="h-4 w-4 text-primary" />
              Locale & Timezone
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="org-locale">Display Locale</Label>
                <Select
                  value={selectedLocale}
                  onValueChange={(val) => {
                    setSelectedLocale(val);
                    updateLocaleTimezone.mutate({ locale: val });
                  }}
                >
                  <SelectTrigger id="org-locale" data-testid="select-locale">
                    <SelectValue placeholder="Select locale" />
                  </SelectTrigger>
                  <SelectContent>
                    {SUPPORTED_LOCALES.map((loc) => (
                      <SelectItem key={loc.value} value={loc.value}>
                        {loc.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  Controls date, number, and currency formatting across the platform.
                </p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="org-timezone">Organization Timezone</Label>
                <Select
                  value={selectedTimezone}
                  onValueChange={(val) => {
                    setSelectedTimezone(val);
                    updateLocaleTimezone.mutate({ timezone: val });
                  }}
                >
                  <SelectTrigger id="org-timezone" data-testid="select-timezone">
                    <SelectValue placeholder="Select timezone" />
                  </SelectTrigger>
                  <SelectContent>
                    {COMMON_TIMEZONES.map((tz) => (
                      <SelectItem key={tz.value} value={tz.value}>
                        {tz.label} ({tz.value})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  Used for report scheduling, SLA calculations, and time display across all pages.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function AuditTrailTab({ orgId }: { orgId: string }) {
  const { data: auditLogs, isLoading } = useQuery<any[]>({
    queryKey: ["/api/audit-logs"],
    enabled: !!orgId,
  });

  const filteredLogs =
    auditLogs?.filter((log: any) => log.resourceType === "membership" || log.resourceType === "invitation") || [];

  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-4 space-y-3">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="flex items-center gap-4">
              <Skeleton className="h-4 flex-1" />
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-4 w-32" />
            </div>
          ))}
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-semibold flex items-center gap-2 flex-wrap">
          <ScrollText className="h-4 w-4 text-muted-foreground" />
          Membership Audit Trail
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto border rounded-md">
          <Table data-testid="table-audit-trail">
            <TableHeader>
              <TableRow>
                <TableHead className="text-xs">Action</TableHead>
                <TableHead className="text-xs">User</TableHead>
                <TableHead className="text-xs">Details</TableHead>
                <TableHead className="text-xs">Timestamp</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredLogs.length > 0 ? (
                filteredLogs.map((log: any) => (
                  <TableRow key={log.id} data-testid={`row-audit-${log.id}`}>
                    <TableCell>
                      <Badge
                        variant="outline"
                        className="no-default-hover-elevate no-default-active-elevate text-[10px]"
                        data-testid={`badge-audit-action-${log.id}`}
                      >
                        {log.action}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs" data-testid={`text-audit-user-${log.id}`}>
                        {log.userEmail || log.userId || "System"}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs text-muted-foreground" data-testid={`text-audit-details-${log.id}`}>
                        {log.details
                          ? typeof log.details === "string"
                            ? log.details
                            : JSON.stringify(log.details)
                          : "—"}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs text-muted-foreground" data-testid={`text-audit-time-${log.id}`}>
                        {formatDateTime(log.createdAt || log.timestamp)}
                      </span>
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell colSpan={4} className="text-center text-sm text-muted-foreground py-8">
                    No audit entries found
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}

export default function TeamManagementPage() {
  const { orgId, orgRole, organization, isLoading } = useOrgContext();

  if (isLoading) {
    return (
      <div className="p-4 md:p-6 space-y-6 max-w-5xl mx-auto">
        <div>
          <Skeleton className="h-7 w-48" />
          <Skeleton className="h-4 w-64 mt-2" />
        </div>
        <Card>
          <CardContent className="p-6 space-y-4">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-40 w-full" />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!orgId) {
    return (
      <div className="p-4 md:p-6 space-y-6 max-w-5xl mx-auto">
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 gap-3">
            <AlertTriangle className="h-8 w-8 text-muted-foreground" />
            <div className="text-sm text-muted-foreground">Unable to load organization context. Please try again.</div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-5xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">
          <span className="gradient-text-red">Team Management</span>
        </h1>
        <p className="text-sm text-muted-foreground mt-1">
          Manage members, invitations, and roles for {organization?.name || "your organization"}
        </p>
        <div className="gradient-accent-line w-24 mt-2" />
      </div>

      <Tabs defaultValue="members" className="space-y-4">
        <TabsList data-testid="tabs-team">
          <TabsTrigger value="members" data-testid="tab-members">
            <Users className="h-4 w-4 mr-1.5" />
            Members
          </TabsTrigger>
          <TabsTrigger value="invitations" data-testid="tab-invitations">
            <Mail className="h-4 w-4 mr-1.5" />
            Invitations
          </TabsTrigger>
          <TabsTrigger value="security" data-testid="tab-security">
            <Lock className="h-4 w-4 mr-1.5" />
            Security
          </TabsTrigger>
          <TabsTrigger value="audit" data-testid="tab-audit">
            <ScrollText className="h-4 w-4 mr-1.5" />
            Audit Trail
          </TabsTrigger>
        </TabsList>

        <TabsContent value="members">
          <MembersTab orgId={orgId} orgRole={orgRole} />
        </TabsContent>

        <TabsContent value="invitations">
          <InvitationsTab orgId={orgId} orgRole={orgRole} />
        </TabsContent>

        <TabsContent value="security">
          <SecurityTab orgId={orgId} orgRole={orgRole} />
        </TabsContent>

        <TabsContent value="audit">
          <AuditTrailTab orgId={orgId} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
