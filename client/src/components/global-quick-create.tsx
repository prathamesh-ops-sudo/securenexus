import { useState, useCallback } from "react";
import { useLocation } from "wouter";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
  DropdownMenuLabel,
} from "@/components/ui/dropdown-menu";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogClose,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Plus, StickyNote, ListTodo, Bell, FileWarning, Loader2 } from "lucide-react";

type QuickCreateMode = null | "alert-note" | "incident-task" | "notification-channel";

export function GlobalQuickCreate() {
  const [mode, setMode] = useState<QuickCreateMode>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const { toast } = useToast();
  const [, navigate] = useLocation();
  const [noteAlertId, setNoteAlertId] = useState("");
  const [noteContent, setNoteContent] = useState("");
  const [taskTitle, setTaskTitle] = useState("");
  const [taskSeverity, setTaskSeverity] = useState("medium");
  const [channelName, setChannelName] = useState("");
  const [channelType, setChannelType] = useState("");

  const resetForm = useCallback(() => {
    setNoteAlertId(""); setNoteContent(""); setTaskTitle(""); setTaskSeverity("medium"); setChannelName(""); setChannelType(""); setMode(null);
  }, []);

  const handleSubmitNote = useCallback(async () => {
    if (!noteContent.trim()) { toast({ title: "Note content required", variant: "destructive" }); return; }
    setIsSubmitting(true);
    try {
      if (noteAlertId.trim()) {
        await apiRequest("PATCH", `/api/alerts/${noteAlertId.trim()}`, { notes: noteContent.trim() });
        queryClient.invalidateQueries({ queryKey: ["/api/alerts"] });
        toast({ title: "Note added to alert" });
      } else {
        toast({ title: "Note saved", description: "Navigate to an alert to attach the note" });
      }
      resetForm();
    } catch { toast({ title: "Failed to save note", variant: "destructive" }); }
    finally { setIsSubmitting(false); }
  }, [noteAlertId, noteContent, toast, resetForm]);

  const handleSubmitTask = useCallback(async () => {
    if (!taskTitle.trim()) { toast({ title: "Title required", variant: "destructive" }); return; }
    setIsSubmitting(true);
    try {
      await apiRequest("POST", "/api/incidents", { title: taskTitle.trim(), severity: taskSeverity, status: "open" });
      queryClient.invalidateQueries({ queryKey: ["/api/incidents"] });
      toast({ title: "Incident created", description: taskTitle.trim() });
      resetForm(); navigate("/incidents");
    } catch { toast({ title: "Failed to create incident", variant: "destructive" }); }
    finally { setIsSubmitting(false); }
  }, [taskTitle, taskSeverity, toast, resetForm, navigate]);

  const handleSubmitChannel = useCallback(async () => {
    if (!channelName.trim() || !channelType) { toast({ title: "Name and type required", variant: "destructive" }); return; }
    setIsSubmitting(true);
    try {
      await apiRequest("POST", "/api/notification-channels", { name: channelName.trim(), type: channelType, config: {}, events: [], isDefault: false });
      queryClient.invalidateQueries({ queryKey: ["/api/notification-channels"] });
      toast({ title: "Channel created", description: channelName.trim() });
      resetForm(); navigate("/integrations");
    } catch { toast({ title: "Failed to create channel", variant: "destructive" }); }
    finally { setIsSubmitting(false); }
  }, [channelName, channelType, toast, resetForm, navigate]);

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button size="icon" variant="default" className="fixed bottom-6 right-6 z-50 h-12 w-12 rounded-full shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105 active:scale-95" data-testid="button-global-quick-create">
            <Plus className="h-5 w-5" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" side="top" className="w-56 mb-2">
          <DropdownMenuLabel className="text-xs text-muted-foreground">Quick Create</DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem onClick={() => setMode("alert-note")} data-testid="quick-create-alert-note">
            <StickyNote className="h-4 w-4 mr-2" />Alert Note
          </DropdownMenuItem>
          <DropdownMenuItem onClick={() => setMode("incident-task")} data-testid="quick-create-incident-task">
            <ListTodo className="h-4 w-4 mr-2" />Incident / Task
          </DropdownMenuItem>
          <DropdownMenuItem onClick={() => setMode("notification-channel")} data-testid="quick-create-notification-channel">
            <Bell className="h-4 w-4 mr-2" />Notification Channel
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <Dialog open={mode === "alert-note"} onOpenChange={(open) => { if (!open) resetForm(); }}>
        <DialogContent className="max-w-md">
          <DialogHeader><DialogTitle className="flex items-center gap-2"><StickyNote className="h-4 w-4" />Add Alert Note</DialogTitle></DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label htmlFor="qc-alert-id">Alert ID <span className="text-muted-foreground text-xs">(optional)</span></Label>
              <Input id="qc-alert-id" placeholder="e.g. alert-abc123" value={noteAlertId} onChange={(e) => setNoteAlertId(e.target.value)} data-testid="input-qc-alert-id" />
            </div>
            <div className="space-y-2">
              <Label htmlFor="qc-note-content">Note</Label>
              <Textarea id="qc-note-content" placeholder="Add investigation notes, findings, or context..." value={noteContent} onChange={(e) => setNoteContent(e.target.value)} rows={4} data-testid="input-qc-note-content" />
              {!noteContent.trim() && noteContent.length > 0 && <p className="text-xs text-destructive">Note content cannot be empty</p>}
            </div>
          </div>
          <DialogFooter>
            <DialogClose asChild><Button variant="outline">Cancel</Button></DialogClose>
            <Button onClick={handleSubmitNote} disabled={!noteContent.trim() || isSubmitting} data-testid="button-qc-submit-note">
              {isSubmitting ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <StickyNote className="h-4 w-4 mr-2" />}Save Note
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={mode === "incident-task"} onOpenChange={(open) => { if (!open) resetForm(); }}>
        <DialogContent className="max-w-md">
          <DialogHeader><DialogTitle className="flex items-center gap-2"><FileWarning className="h-4 w-4" />Create Incident</DialogTitle></DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label htmlFor="qc-task-title">Title</Label>
              <Input id="qc-task-title" placeholder="Incident title..." value={taskTitle} onChange={(e) => setTaskTitle(e.target.value)} data-testid="input-qc-task-title" />
              {!taskTitle.trim() && taskTitle.length > 0 && <p className="text-xs text-destructive">Title is required</p>}
            </div>
            <div className="space-y-2">
              <Label>Severity</Label>
              <Select value={taskSeverity} onValueChange={setTaskSeverity}>
                <SelectTrigger data-testid="select-qc-severity"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <DialogClose asChild><Button variant="outline">Cancel</Button></DialogClose>
            <Button onClick={handleSubmitTask} disabled={!taskTitle.trim() || isSubmitting} data-testid="button-qc-submit-task">
              {isSubmitting ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Plus className="h-4 w-4 mr-2" />}Create Incident
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={mode === "notification-channel"} onOpenChange={(open) => { if (!open) resetForm(); }}>
        <DialogContent className="max-w-md">
          <DialogHeader><DialogTitle className="flex items-center gap-2"><Bell className="h-4 w-4" />Add Notification Channel</DialogTitle></DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label htmlFor="qc-channel-name">Channel Name</Label>
              <Input id="qc-channel-name" placeholder="e.g. Security Alerts Slack" value={channelName} onChange={(e) => setChannelName(e.target.value)} data-testid="input-qc-channel-name" />
              {!channelName.trim() && channelName.length > 0 && <p className="text-xs text-destructive">Channel name is required</p>}
            </div>
            <div className="space-y-2">
              <Label>Type</Label>
              <Select value={channelType} onValueChange={setChannelType}>
                <SelectTrigger data-testid="select-qc-channel-type"><SelectValue placeholder="Select channel type..." /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="slack">Slack</SelectItem>
                  <SelectItem value="teams">Teams</SelectItem>
                  <SelectItem value="email">Email</SelectItem>
                  <SelectItem value="webhook">Webhook</SelectItem>
                  <SelectItem value="pagerduty">PagerDuty</SelectItem>
                </SelectContent>
              </Select>
              {!channelType && channelName.trim() && <p className="text-xs text-destructive">Please select a channel type</p>}
            </div>
          </div>
          <DialogFooter>
            <DialogClose asChild><Button variant="outline">Cancel</Button></DialogClose>
            <Button onClick={handleSubmitChannel} disabled={!channelName.trim() || !channelType || isSubmitting} data-testid="button-qc-submit-channel">
              {isSubmitting ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Plus className="h-4 w-4 mr-2" />}Create Channel
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
