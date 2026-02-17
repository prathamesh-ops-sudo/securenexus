import { useState, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import {
  Users, Shield, UserPlus, Clock, Mail, Loader2,
  MoreHorizontal, UserX, UserCheck, Trash2, ScrollText,
  Crown, ShieldCheck, Eye, AlertTriangle,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogClose,
} from "@/components/ui/dialog";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Skeleton } from "@/components/ui/skeleton";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/use-auth";

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

function formatDate(date: string | null | undefined): string {
  if (!date) return "N/A";
  return new Date(date).toLocaleDateString("en-US", {
    year: "numeric", month: "short", day: "numeric",
  });
}

function formatDateTime(date: string | null | undefined): string {
  if (!date) return "N/A";
  return new Date(date).toLocaleString("en-US", {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

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

  const { data, isLoading: queryLoading } = useQuery<any>({
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

  const { data: members, isLoading } = useQuery<any[]>({
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
                                <div className="text-xs text-muted-foreground" data-testid={`text-member-email-${member.id}`}>
                                  {member.user.email}
                                </div>
                              )}
                              {!member.user?.email && member.email && (
                                <div className="text-xs text-muted-foreground" data-testid={`text-member-email-${member.id}`}>
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
              Changing role for <span className="font-medium text-foreground">{selectedMember?.user?.email || selectedMember?.email || "member"}</span>
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
              <Button variant="outline" data-testid="button-cancel-role-change">Cancel</Button>
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
                        <span className="text-sm" data-testid={`text-invite-email-${inv.id}`}>{inv.email}</span>
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
              <Button variant="outline" data-testid="button-cancel-invite">Cancel</Button>
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

function AuditTrailTab({ orgId }: { orgId: string }) {
  const { data: auditLogs, isLoading } = useQuery<any[]>({
    queryKey: ["/api/audit-logs"],
    enabled: !!orgId,
  });

  const filteredLogs = auditLogs?.filter(
    (log: any) => log.resourceType === "membership" || log.resourceType === "invitation"
  ) || [];

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
                        {log.details ? (typeof log.details === "string" ? log.details : JSON.stringify(log.details)) : "—"}
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

        <TabsContent value="audit">
          <AuditTrailTab orgId={orgId} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
