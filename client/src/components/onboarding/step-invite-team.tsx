import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Button } from "@/components/ui/button";

export function StepInviteTeam({
  isSubmitting,
  onInvite,
  onSkip,
}: {
  isSubmitting: boolean;
  onInvite: (invites: Array<{ email: string; role: string }>) => Promise<void>;
  onSkip: () => Promise<void>;
}) {
  const [emailsText, setEmailsText] = useState("");
  const [role, setRole] = useState("analyst");

  const parsedEmails = emailsText
    .split(/[\n,;]/g)
    .map((v) => v.trim())
    .filter(Boolean);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Invite your team</CardTitle>
        <CardDescription>Add multiple emails at once. You can skip this step for now.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          <Label>Emails (comma or new line separated)</Label>
          <Textarea
            value={emailsText}
            onChange={(e) => setEmailsText(e.target.value)}
            placeholder={"alice@company.com\nbob@company.com"}
            rows={6}
          />
        </div>
        <div className="space-y-2">
          <Label>Role for invited users</Label>
          <Select value={role} onValueChange={setRole}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="admin">Admin</SelectItem>
              <SelectItem value="analyst">Analyst</SelectItem>
              <SelectItem value="read_only">Read-only</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="flex gap-2">
          <Button
            className="flex-1"
            disabled={isSubmitting || parsedEmails.length === 0}
            onClick={() => onInvite(parsedEmails.map((email) => ({ email, role })))}
          >
            {isSubmitting ? "Inviting..." : "Send invites"}
          </Button>
          <Button variant="outline" disabled={isSubmitting} onClick={onSkip}>
            Skip for now
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
