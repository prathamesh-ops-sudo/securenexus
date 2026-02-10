import { Settings, Shield, Bell, Key, Globe } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/hooks/use-auth";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";

export default function SettingsPage() {
  const { user } = useAuth();

  const initials = user
    ? `${user.firstName?.[0] || ""}${user.lastName?.[0] || ""}`.toUpperCase() || "U"
    : "U";

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-3xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight" data-testid="text-page-title">Settings</h1>
        <p className="text-sm text-muted-foreground mt-1">Manage your account and platform preferences</p>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Profile</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-4">
            <Avatar className="h-14 w-14">
              <AvatarImage src={user?.profileImageUrl || ""} />
              <AvatarFallback>{initials}</AvatarFallback>
            </Avatar>
            <div>
              <div className="font-semibold" data-testid="text-user-name">{user?.firstName} {user?.lastName}</div>
              <div className="text-sm text-muted-foreground" data-testid="text-user-email">{user?.email || "No email"}</div>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {[
          { icon: Bell, title: "Notifications", description: "Configure alert notification preferences", status: "Coming in Phase 3" },
          { icon: Key, title: "API Keys", description: "Manage API keys for tool integrations", status: "Coming in Phase 2" },
          { icon: Globe, title: "Integrations", description: "Connect EDR, SIEM, and cloud security tools", status: "Coming in Phase 2" },
          { icon: Shield, title: "Security", description: "MFA, session management, and access controls", status: "Coming in Phase 11" },
        ].map((item, i) => (
          <Card key={i} className="opacity-60" data-testid={`card-setting-${item.title.toLowerCase()}`}>
            <CardContent className="p-4">
              <div className="flex items-start gap-3">
                <div className="flex items-center justify-center w-9 h-9 rounded-md bg-muted flex-shrink-0">
                  <item.icon className="h-4 w-4 text-muted-foreground" />
                </div>
                <div>
                  <div className="text-sm font-medium">{item.title}</div>
                  <div className="text-xs text-muted-foreground mt-0.5">{item.description}</div>
                  <span className="inline-block mt-2 px-2 py-0.5 rounded text-[10px] bg-muted text-muted-foreground">{item.status}</span>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
