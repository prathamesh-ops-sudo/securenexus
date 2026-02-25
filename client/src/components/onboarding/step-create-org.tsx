import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Button } from "@/components/ui/button";

type CreateOrgPayload = {
  name: string;
  industry: string;
  companySize: string;
  contactEmail?: string;
};

export function StepCreateOrg({
  defaultEmail,
  isSubmitting,
  onSubmit,
}: {
  defaultEmail?: string;
  isSubmitting: boolean;
  onSubmit: (payload: CreateOrgPayload) => Promise<void>;
}) {
  const [name, setName] = useState("");
  const [industry, setIndustry] = useState("");
  const [companySize, setCompanySize] = useState("1-10");
  const [contactEmail, setContactEmail] = useState(defaultEmail || "");

  return (
    <Card>
      <CardHeader>
        <CardTitle>Create organization</CardTitle>
        <CardDescription>Set up your organization profile before selecting a plan.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="org-name">Organization name</Label>
          <Input id="org-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme Security" />
        </div>
        <div className="space-y-2">
          <Label htmlFor="org-industry">Industry</Label>
          <Input id="org-industry" value={industry} onChange={(e) => setIndustry(e.target.value)} placeholder="Fintech, Healthcare, SaaS..." />
        </div>
        <div className="space-y-2">
          <Label>Company size</Label>
          <Select value={companySize} onValueChange={setCompanySize}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="1-10">1-10</SelectItem>
              <SelectItem value="11-50">11-50</SelectItem>
              <SelectItem value="51-200">51-200</SelectItem>
              <SelectItem value="201-1000">201-1000</SelectItem>
              <SelectItem value="1000+">1000+</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label htmlFor="org-contact">Contact email</Label>
          <Input id="org-contact" value={contactEmail} onChange={(e) => setContactEmail(e.target.value)} placeholder="security@acme.com" />
        </div>
        <Button
          className="w-full"
          disabled={isSubmitting || name.trim().length < 2}
          onClick={() => onSubmit({ name: name.trim(), industry: industry.trim(), companySize, contactEmail: contactEmail.trim() || undefined })}
        >
          {isSubmitting ? "Creating..." : "Continue"}
        </Button>
      </CardContent>
    </Card>
  );
}
