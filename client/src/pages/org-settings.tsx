import { useState, useRef } from "react";
import {
  Building2,
  Mail,
  Phone,
  MapPin,
  Palette,
  Upload,
  Trash2,
  AlertTriangle,
  Loader2,
  Crown,
  ArrowRightLeft,
  Image,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useOrgContext } from "@/hooks/use-org-context";

const INDUSTRIES = [
  "Technology",
  "Financial Services",
  "Healthcare",
  "Government",
  "Education",
  "Retail",
  "Manufacturing",
  "Energy",
  "Telecommunications",
  "Legal",
  "Media",
  "Non-Profit",
  "Other",
];

const COMPANY_SIZES = ["1-10", "11-50", "51-200", "201-500", "501-1000", "1001-5000", "5001-10000", "10000+"];

const TIMEZONES = [
  "UTC",
  "America/New_York",
  "America/Chicago",
  "America/Denver",
  "America/Los_Angeles",
  "Europe/London",
  "Europe/Berlin",
  "Europe/Paris",
  "Asia/Tokyo",
  "Asia/Shanghai",
  "Asia/Kolkata",
  "Australia/Sydney",
];

interface OrgSettings {
  id: string;
  name: string;
  slug: string;
  industry: string | null;
  contactEmail: string | null;
  billingEmail: string | null;
  phone: string | null;
  address: { street?: string; city?: string; state?: string; zip?: string; country?: string } | null;
  companySize: string | null;
  logoUrl: string | null;
  logoSignedUrl: string | null;
  primaryColor: string | null;
  timezone: string | null;
  locale: string | null;
  maxUsers: number | null;
  createdAt: string | null;
  updatedAt: string | null;
}

export default function OrgSettingsPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const { currentOrgId, currentRole, memberships } = useOrgContext();

  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [deleteConfirmName, setDeleteConfirmName] = useState("");
  const [transferDialogOpen, setTransferDialogOpen] = useState(false);
  const [transferTargetId, setTransferTargetId] = useState("");
  const logoInputRef = useRef<HTMLInputElement>(null);

  const isOwner = currentRole === "owner";
  const isAdmin = currentRole === "admin" || isOwner;

  const {
    data: org,
    isLoading,
    isError,
    refetch,
  } = useQuery<OrgSettings>({
    queryKey: [`/api/orgs/${currentOrgId}/settings`],
    enabled: !!currentOrgId,
  });

  const { data: members } = useQuery<any[]>({
    queryKey: [`/api/orgs/${currentOrgId}/members`],
    enabled: !!currentOrgId,
  });

  const [form, setForm] = useState<Record<string, any>>({});

  const updateField = (field: string, value: unknown) => {
    setForm((prev) => ({ ...prev, [field]: value }));
  };

  const getFieldValue = (field: string, fallback: unknown = "") => {
    if (form[field] !== undefined) return form[field];
    if (!org) return fallback;
    if (field.startsWith("address.")) {
      const subField = field.replace("address.", "");
      return (org.address as any)?.[subField] ?? fallback;
    }
    return (org as any)?.[field] ?? fallback;
  };

  const updateSettings = useMutation({
    mutationFn: async (data: Record<string, unknown>) => {
      const res = await apiRequest("PUT", `/api/orgs/${currentOrgId}/settings`, data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/orgs/${currentOrgId}/settings`] });
      queryClient.invalidateQueries({ queryKey: ["/api/auth/me"] });
      setForm({});
      toast({ title: "Settings updated", description: "Organization settings saved successfully." });
    },
    onError: (error: Error) => {
      toast({ title: "Update failed", description: error.message, variant: "destructive" });
    },
  });

  const uploadLogo = useMutation({
    mutationFn: async (file: File) => {
      const formData = new FormData();
      formData.append("logo", file);
      const hdrs: Record<string, string> = {};
      const csrfMatch = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]*)/);
      if (csrfMatch) hdrs["X-CSRF-Token"] = decodeURIComponent(csrfMatch[1]);
      try {
        const activeOrgId = localStorage.getItem("securenexus.activeOrgId");
        if (activeOrgId) hdrs["X-Org-Id"] = activeOrgId;
      } catch {
        /* privacy mode */
      }
      const res = await fetch(`/api/orgs/${currentOrgId}/logo`, {
        method: "POST",
        body: formData,
        credentials: "include",
        headers: hdrs,
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ message: "Upload failed" }));
        throw new Error(err.error || err.message || "Upload failed");
      }
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/orgs/${currentOrgId}/settings`] });
      toast({ title: "Logo uploaded", description: "Organization logo updated successfully." });
    },
    onError: (error: Error) => {
      toast({ title: "Upload failed", description: error.message, variant: "destructive" });
    },
  });

  const removeLogo = useMutation({
    mutationFn: async () => {
      await apiRequest("DELETE", `/api/orgs/${currentOrgId}/logo`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/orgs/${currentOrgId}/settings`] });
      toast({ title: "Logo removed" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to remove logo", description: error.message, variant: "destructive" });
    },
  });

  const deleteOrg = useMutation({
    mutationFn: async (confirmName: string) => {
      await apiRequest("DELETE", `/api/orgs/${currentOrgId}`, { confirmName });
    },
    onSuccess: () => {
      setDeleteDialogOpen(false);
      queryClient.invalidateQueries();
      toast({ title: "Organization deleted", description: "The organization has been permanently deleted." });
      window.location.href = "/";
    },
    onError: (error: Error) => {
      toast({ title: "Delete failed", description: error.message, variant: "destructive" });
    },
  });

  const transferOwnership = useMutation({
    mutationFn: async (targetUserId: string) => {
      await apiRequest("POST", `/api/orgs/${currentOrgId}/transfer-ownership`, { targetUserId });
    },
    onSuccess: () => {
      setTransferDialogOpen(false);
      setTransferTargetId("");
      queryClient.invalidateQueries();
      toast({ title: "Ownership transferred", description: "You are now an admin of this organization." });
    },
    onError: (error: Error) => {
      toast({ title: "Transfer failed", description: error.message, variant: "destructive" });
    },
  });

  const handleSaveGeneral = () => {
    const data: Record<string, unknown> = {};
    const fields = ["name", "industry", "companySize", "timezone"];
    for (const f of fields) {
      if (form[f] !== undefined) data[f] = form[f];
    }
    if (Object.keys(data).length === 0) {
      toast({ title: "No changes", description: "No fields have been modified." });
      return;
    }
    updateSettings.mutate(data);
  };

  const handleSaveContact = () => {
    const data: Record<string, unknown> = {};
    if (form.contactEmail !== undefined) data.contactEmail = form.contactEmail;
    if (form.billingEmail !== undefined) data.billingEmail = form.billingEmail;
    if (form.phone !== undefined) data.phone = form.phone;

    const addressFields = ["street", "city", "state", "zip", "country"];
    const hasAddressChange = addressFields.some((f) => form[`address.${f}`] !== undefined);
    if (hasAddressChange) {
      const currentAddress = (org?.address as any) || {};
      data.address = {
        street: form["address.street"] ?? currentAddress.street ?? "",
        city: form["address.city"] ?? currentAddress.city ?? "",
        state: form["address.state"] ?? currentAddress.state ?? "",
        zip: form["address.zip"] ?? currentAddress.zip ?? "",
        country: form["address.country"] ?? currentAddress.country ?? "",
      };
    }

    if (Object.keys(data).length === 0) {
      toast({ title: "No changes", description: "No fields have been modified." });
      return;
    }
    updateSettings.mutate(data);
  };

  const handleSaveBranding = () => {
    const data: Record<string, unknown> = {};
    if (form.primaryColor !== undefined) data.primaryColor = form.primaryColor;
    if (Object.keys(data).length === 0) {
      toast({ title: "No changes", description: "No fields have been modified." });
      return;
    }
    updateSettings.mutate(data);
  };

  const handleLogoSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 2 * 1024 * 1024) {
      toast({ title: "File too large", description: "Logo must be under 2MB.", variant: "destructive" });
      return;
    }
    uploadLogo.mutate(file);
  };

  if (!currentOrgId) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <Building2 className="h-10 w-10 text-muted-foreground mb-3" />
        <p className="text-sm font-medium">No organization selected</p>
        <p className="text-xs text-muted-foreground mt-1">Select or create an organization to manage its settings.</p>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="p-4 md:p-6 space-y-6 max-w-4xl mx-auto" role="status" aria-label="Loading organization settings">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-48" />
        <Skeleton className="h-48" />
        <Skeleton className="h-48" />
        <span className="sr-only">Loading organization settings...</span>
      </div>
    );
  }

  if (isError || !org) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center" role="alert">
        <div className="rounded-full bg-destructive/10 p-3 ring-1 ring-destructive/20 mb-3">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <p className="text-sm font-medium">Failed to load organization settings</p>
        <p className="text-xs text-muted-foreground mt-1">An error occurred while fetching data.</p>
        <Button variant="outline" size="sm" className="mt-3" onClick={() => refetch()}>
          Try Again
        </Button>
      </div>
    );
  }

  const activeMembers = members?.filter((m: any) => m.status === "active" && m.userId !== undefined) ?? [];

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-4xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">
          <span className="gradient-text-brand">Organization Settings</span>
        </h1>
        <p className="text-sm text-muted-foreground mt-1">Manage {org.name} settings, branding, and configuration</p>
        <div className="gradient-accent-line w-24 mt-2" />
      </div>

      {/* General Section */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Building2 className="h-4 w-4" />
            General
          </CardTitle>
          <CardDescription className="text-xs">Basic organization information</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <Label htmlFor="org-name" className="text-xs">
                Organization Name
              </Label>
              <Input
                id="org-name"
                value={getFieldValue("name")}
                onChange={(e) => updateField("name", e.target.value)}
                disabled={!isAdmin}
                placeholder="Acme Corp"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="org-slug" className="text-xs">
                Slug (read-only)
              </Label>
              <Input id="org-slug" value={org.slug} disabled className="bg-muted/50" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="org-industry" className="text-xs">
                Industry
              </Label>
              <Select
                value={getFieldValue("industry", "") as string}
                onValueChange={(v) => updateField("industry", v)}
                disabled={!isAdmin}
              >
                <SelectTrigger id="org-industry">
                  <SelectValue placeholder="Select industry" />
                </SelectTrigger>
                <SelectContent>
                  {INDUSTRIES.map((i) => (
                    <SelectItem key={i} value={i}>
                      {i}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="org-size" className="text-xs">
                Company Size
              </Label>
              <Select
                value={getFieldValue("companySize", "") as string}
                onValueChange={(v) => updateField("companySize", v)}
                disabled={!isAdmin}
              >
                <SelectTrigger id="org-size">
                  <SelectValue placeholder="Select size" />
                </SelectTrigger>
                <SelectContent>
                  {COMPANY_SIZES.map((s) => (
                    <SelectItem key={s} value={s}>
                      {s} employees
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="org-timezone" className="text-xs">
                Timezone
              </Label>
              <Select
                value={getFieldValue("timezone", "UTC") as string}
                onValueChange={(v) => updateField("timezone", v)}
                disabled={!isAdmin}
              >
                <SelectTrigger id="org-timezone">
                  <SelectValue placeholder="Select timezone" />
                </SelectTrigger>
                <SelectContent>
                  {TIMEZONES.map((tz) => (
                    <SelectItem key={tz} value={tz}>
                      {tz}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          {isAdmin && (
            <div className="flex justify-end pt-2">
              <Button size="sm" onClick={handleSaveGeneral} disabled={updateSettings.isPending}>
                {updateSettings.isPending && <Loader2 className="h-3 w-3 mr-1 animate-spin" />}
                Save General
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Contact Section */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Mail className="h-4 w-4" />
            Contact Information
          </CardTitle>
          <CardDescription className="text-xs">Organization contact and billing details</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <Label htmlFor="contact-email" className="text-xs">
                Contact Email
              </Label>
              <Input
                id="contact-email"
                type="email"
                value={getFieldValue("contactEmail")}
                onChange={(e) => updateField("contactEmail", e.target.value)}
                disabled={!isAdmin}
                placeholder="contact@example.com"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="billing-email" className="text-xs">
                Billing Email
              </Label>
              <Input
                id="billing-email"
                type="email"
                value={getFieldValue("billingEmail")}
                onChange={(e) => updateField("billingEmail", e.target.value)}
                disabled={!isAdmin}
                placeholder="billing@example.com"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="phone" className="text-xs">
                Phone
              </Label>
              <Input
                id="phone"
                value={getFieldValue("phone")}
                onChange={(e) => updateField("phone", e.target.value)}
                disabled={!isAdmin}
                placeholder="+1 (555) 000-0000"
              />
            </div>
          </div>

          <Separator className="my-2" />

          <div className="space-y-1.5">
            <Label className="text-xs flex items-center gap-1.5">
              <MapPin className="h-3 w-3" />
              Address
            </Label>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <Input
                placeholder="Street"
                value={getFieldValue("address.street")}
                onChange={(e) => updateField("address.street", e.target.value)}
                disabled={!isAdmin}
              />
              <Input
                placeholder="City"
                value={getFieldValue("address.city")}
                onChange={(e) => updateField("address.city", e.target.value)}
                disabled={!isAdmin}
              />
              <Input
                placeholder="State / Region"
                value={getFieldValue("address.state")}
                onChange={(e) => updateField("address.state", e.target.value)}
                disabled={!isAdmin}
              />
              <Input
                placeholder="ZIP / Postal Code"
                value={getFieldValue("address.zip")}
                onChange={(e) => updateField("address.zip", e.target.value)}
                disabled={!isAdmin}
              />
              <Input
                placeholder="Country"
                value={getFieldValue("address.country")}
                onChange={(e) => updateField("address.country", e.target.value)}
                disabled={!isAdmin}
                className="md:col-span-2"
              />
            </div>
          </div>

          {isAdmin && (
            <div className="flex justify-end pt-2">
              <Button size="sm" onClick={handleSaveContact} disabled={updateSettings.isPending}>
                {updateSettings.isPending && <Loader2 className="h-3 w-3 mr-1 animate-spin" />}
                Save Contact
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Branding Section */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Palette className="h-4 w-4" />
            Branding
          </CardTitle>
          <CardDescription className="text-xs">Organization logo and color theme</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-start gap-6">
            <div className="space-y-2">
              <Label className="text-xs">Organization Logo</Label>
              <div className="flex items-center gap-3">
                <div className="w-16 h-16 rounded-lg border border-dashed border-border flex items-center justify-center bg-muted/30 overflow-hidden">
                  {org.logoSignedUrl ? (
                    <img src={org.logoSignedUrl} alt="Org logo" className="w-full h-full object-contain" />
                  ) : (
                    <Image className="h-6 w-6 text-muted-foreground" />
                  )}
                </div>
                {isAdmin && (
                  <div className="flex flex-col gap-1.5">
                    <input
                      ref={logoInputRef}
                      type="file"
                      accept="image/png,image/jpeg,image/webp,image/svg+xml"
                      className="hidden"
                      onChange={handleLogoSelect}
                    />
                    <Button
                      variant="outline"
                      size="sm"
                      className="text-xs"
                      onClick={() => logoInputRef.current?.click()}
                      disabled={uploadLogo.isPending}
                    >
                      {uploadLogo.isPending ? (
                        <Loader2 className="h-3 w-3 mr-1 animate-spin" />
                      ) : (
                        <Upload className="h-3 w-3 mr-1" />
                      )}
                      Upload Logo
                    </Button>
                    {org.logoUrl && (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-xs text-destructive"
                        onClick={() => removeLogo.mutate()}
                        disabled={removeLogo.isPending}
                      >
                        <Trash2 className="h-3 w-3 mr-1" />
                        Remove
                      </Button>
                    )}
                    <p className="text-[10px] text-muted-foreground">PNG, JPEG, WebP, or SVG. Max 2MB.</p>
                  </div>
                )}
              </div>
            </div>
          </div>

          <Separator className="my-2" />

          <div className="space-y-2">
            <Label htmlFor="primary-color" className="text-xs">
              Primary Brand Color
            </Label>
            <div className="flex items-center gap-3">
              <input
                type="color"
                id="primary-color"
                value={getFieldValue("primaryColor", "#0EA5E9") as string}
                onChange={(e) => updateField("primaryColor", e.target.value)}
                disabled={!isAdmin}
                className="w-10 h-10 rounded cursor-pointer border border-border"
              />
              <Input
                value={getFieldValue("primaryColor", "#0EA5E9")}
                onChange={(e) => updateField("primaryColor", e.target.value)}
                disabled={!isAdmin}
                placeholder="#0EA5E9"
                className="w-32 font-mono text-xs"
              />
              <div
                className="w-10 h-10 rounded border border-border"
                style={{ backgroundColor: getFieldValue("primaryColor", "#0EA5E9") as string }}
              />
            </div>
          </div>

          {isAdmin && (
            <div className="flex justify-end pt-2">
              <Button size="sm" onClick={handleSaveBranding} disabled={updateSettings.isPending}>
                {updateSettings.isPending && <Loader2 className="h-3 w-3 mr-1 animate-spin" />}
                Save Branding
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Ownership Transfer (owner only) */}
      {isOwner && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <ArrowRightLeft className="h-4 w-4" />
              Transfer Ownership
            </CardTitle>
            <CardDescription className="text-xs">
              Transfer organization ownership to another active member
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-3">
              <Select value={transferTargetId} onValueChange={setTransferTargetId}>
                <SelectTrigger className="w-64">
                  <SelectValue placeholder="Select new owner" />
                </SelectTrigger>
                <SelectContent>
                  {activeMembers
                    .filter((m: any) => m.role !== "owner")
                    .map((m: any) => (
                      <SelectItem key={m.userId} value={m.userId}>
                        {m.invitedEmail || m.userId}
                        <Badge variant="outline" className="ml-2 text-[9px]">
                          {m.role}
                        </Badge>
                      </SelectItem>
                    ))}
                </SelectContent>
              </Select>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  if (!transferTargetId) {
                    toast({
                      title: "Select a member",
                      description: "Choose who to transfer ownership to.",
                      variant: "destructive",
                    });
                    return;
                  }
                  setTransferDialogOpen(true);
                }}
                disabled={!transferTargetId}
              >
                <Crown className="h-3 w-3 mr-1" />
                Transfer
              </Button>
            </div>
            <p className="text-[10px] text-muted-foreground mt-2">
              You will be demoted to Admin after transferring ownership.
            </p>
          </CardContent>
        </Card>
      )}

      {/* Danger Zone (owner only) */}
      {isOwner && (
        <Card className="border-destructive/30">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold text-destructive flex items-center gap-2">
              <AlertTriangle className="h-4 w-4" />
              Danger Zone
            </CardTitle>
            <CardDescription className="text-xs">Irreversible actions. Proceed with extreme caution.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between p-3 rounded-md border border-destructive/20 bg-destructive/5">
              <div>
                <p className="text-sm font-medium">Delete Organization</p>
                <p className="text-xs text-muted-foreground">Permanently delete {org.name} and all associated data.</p>
              </div>
              <Button variant="destructive" size="sm" onClick={() => setDeleteDialogOpen(true)}>
                <Trash2 className="h-3 w-3 mr-1" />
                Delete
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="text-destructive">Delete Organization</DialogTitle>
            <DialogDescription>
              This action is irreversible. All data associated with <strong>{org.name}</strong> will be permanently
              deleted.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <Label htmlFor="confirm-delete" className="text-xs">
              Type <strong>{org.name}</strong> to confirm
            </Label>
            <Input
              id="confirm-delete"
              value={deleteConfirmName}
              onChange={(e) => setDeleteConfirmName(e.target.value)}
              placeholder={org.name}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" size="sm" onClick={() => setDeleteDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              size="sm"
              disabled={deleteConfirmName !== org.name || deleteOrg.isPending}
              onClick={() => deleteOrg.mutate(deleteConfirmName)}
            >
              {deleteOrg.isPending && <Loader2 className="h-3 w-3 mr-1 animate-spin" />}
              Delete Organization
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Transfer Ownership Confirmation Dialog */}
      <Dialog open={transferDialogOpen} onOpenChange={setTransferDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Confirm Ownership Transfer</DialogTitle>
            <DialogDescription>
              You are about to transfer ownership of <strong>{org.name}</strong>. Your role will be changed to Admin.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" size="sm" onClick={() => setTransferDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              size="sm"
              disabled={transferOwnership.isPending}
              onClick={() => transferOwnership.mutate(transferTargetId)}
            >
              {transferOwnership.isPending && <Loader2 className="h-3 w-3 mr-1 animate-spin" />}
              Confirm Transfer
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
