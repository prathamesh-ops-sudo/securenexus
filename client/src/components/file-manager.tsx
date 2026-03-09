import { useState, useCallback, useRef } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import {
  Upload,
  File,
  Trash2,
  Download,
  Loader2,
  FolderOpen,
  AlertTriangle,
  FileText,
  FileImage,
  FileArchive,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from "@/components/ui/dialog";
import { apiRequest, fetchCsrfToken, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

const MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024;
const MAX_FILE_SIZE_LABEL = "50 MB";

const BLOCKED_EXTENSIONS = new Set([
  "exe",
  "bat",
  "cmd",
  "com",
  "msi",
  "scr",
  "pif",
  "vbs",
  "vbe",
  "js",
  "jse",
  "wsf",
  "wsh",
  "ps1",
  "psm1",
  "sh",
  "bash",
  "dll",
  "sys",
  "drv",
]);

interface FileEntry {
  key: string | undefined;
  size: number | undefined;
  lastModified: string | undefined;
  etag: string | undefined;
}

function getFileIcon(filename: string) {
  const ext = filename.split(".").pop()?.toLowerCase() || "";
  if (["png", "jpg", "jpeg", "gif", "svg", "webp", "ico"].includes(ext)) {
    return <FileImage className="h-4 w-4 text-purple-400 shrink-0" />;
  }
  if (["zip", "tar", "gz", "rar", "7z"].includes(ext)) {
    return <FileArchive className="h-4 w-4 text-amber-400 shrink-0" />;
  }
  if (["pdf", "doc", "docx", "txt", "md", "csv", "json", "xml"].includes(ext)) {
    return <FileText className="h-4 w-4 text-blue-400 shrink-0" />;
  }
  return <File className="h-4 w-4 text-muted-foreground shrink-0" />;
}

function formatFileSize(bytes: number | undefined): string {
  if (bytes === undefined || bytes === null) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function extractFilename(key: string | undefined): string {
  if (!key) return "Unknown";
  const parts = key.split("/");
  const rawName = parts[parts.length - 1];
  const tsMatch = rawName.match(/^\d+-(.+)$/);
  return tsMatch ? tsMatch[1] : rawName;
}

export function FileManager({ prefix, title, compact }: { prefix?: string; title?: string; compact?: boolean }) {
  const { toast } = useToast();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<FileEntry | null>(null);

  const queryPrefix = prefix || "uploads/";
  const { data: files, isLoading } = useQuery<FileEntry[]>({
    queryKey: ["/api/files", queryPrefix],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/files?prefix=${encodeURIComponent(queryPrefix)}`);
      const body = await res.json();
      if (body && typeof body === "object" && "data" in body) {
        return (body as { data: FileEntry[] }).data;
      }
      return Array.isArray(body) ? body : [];
    },
  });

  const uploadMutation = useMutation({
    mutationFn: async (file: globalThis.File) => {
      const formData = new FormData();
      formData.append("file", file);
      const headers: Record<string, string> = {};
      try {
        const orgId = localStorage.getItem("securenexus.activeOrgId");
        if (orgId) headers["X-Org-Id"] = orgId;
      } catch {
        /* SSR */
      }
      const csrfToken = await fetchCsrfToken();
      if (csrfToken) headers["X-CSRF-Token"] = csrfToken;

      setUploadProgress(10);
      const res = await fetch(`/api/files/upload?prefix=${encodeURIComponent(queryPrefix)}`, {
        method: "POST",
        body: formData,
        credentials: "include",
        headers,
      });
      setUploadProgress(90);
      if (!res.ok) {
        const errBody = await res.json().catch(() => ({}));
        throw new Error((errBody as { message?: string }).message || `Upload failed (${res.status})`);
      }
      setUploadProgress(100);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/files", queryPrefix] });
      toast({ title: "File uploaded", description: "File has been uploaded successfully" });
      setUploadProgress(null);
    },
    onError: (error: Error) => {
      toast({ title: "Upload failed", description: error.message, variant: "destructive" });
      setUploadProgress(null);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (key: string) => {
      await apiRequest("DELETE", `/api/files/remove?key=${encodeURIComponent(key)}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/files", queryPrefix] });
      toast({ title: "File deleted" });
      setDeleteTarget(null);
    },
    onError: (error: Error) => {
      toast({ title: "Delete failed", description: error.message, variant: "destructive" });
    },
  });

  const downloadFile = useCallback(
    async (key: string) => {
      try {
        const res = await apiRequest("GET", `/api/files/download?key=${encodeURIComponent(key)}`);
        const data = (await res.json()) as { url: string };
        window.open(data.url, "_blank", "noopener,noreferrer");
      } catch (error) {
        toast({
          title: "Download failed",
          description: error instanceof Error ? error.message : "Unknown error",
          variant: "destructive",
        });
      }
    },
    [toast],
  );

  const validateAndUpload = useCallback(
    (file: globalThis.File) => {
      if (file.size > MAX_FILE_SIZE_BYTES) {
        toast({
          title: "File too large",
          description: `Maximum file size is ${MAX_FILE_SIZE_LABEL}. Selected file is ${formatFileSize(file.size)}.`,
          variant: "destructive",
        });
        return;
      }
      const ext = file.name.split(".").pop()?.toLowerCase() || "";
      if (BLOCKED_EXTENSIONS.has(ext)) {
        toast({
          title: "File type blocked",
          description: `Files with .${ext} extension are not allowed for security reasons.`,
          variant: "destructive",
        });
        return;
      }
      uploadMutation.mutate(file);
    },
    [uploadMutation, toast],
  );

  const handleFileSelect = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const selectedFile = e.target.files?.[0];
      if (selectedFile) validateAndUpload(selectedFile);
      e.target.value = "";
    },
    [validateAndUpload],
  );

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragging(false);
      const droppedFile = e.dataTransfer.files[0];
      if (droppedFile) validateAndUpload(droppedFile);
    },
    [validateAndUpload],
  );

  const fileCount = files?.length || 0;

  return (
    <>
      <Card data-testid="file-manager">
        <CardHeader className={compact ? "pb-2 pt-3 px-3" : "pb-3"}>
          <div className="flex items-center justify-between">
            <CardTitle className={compact ? "text-sm flex items-center gap-1.5" : "text-base flex items-center gap-2"}>
              <FolderOpen
                className={compact ? "h-3.5 w-3.5 text-cyan-400" : "h-4 w-4 text-cyan-400"}
                aria-hidden="true"
              />
              {title || "File Manager"}
              <Badge variant="outline" className="text-[9px] ml-1">
                {fileCount}
              </Badge>
            </CardTitle>
            <Button
              variant="outline"
              size="sm"
              className={compact ? "h-6 text-[10px] px-2" : "h-7 text-xs"}
              onClick={() => fileInputRef.current?.click()}
              disabled={uploadMutation.isPending}
              data-testid="button-upload-file"
              aria-label="Upload file"
            >
              {uploadMutation.isPending ? (
                <Loader2 className="h-3 w-3 mr-1 animate-spin" />
              ) : (
                <Upload className="h-3 w-3 mr-1" />
              )}
              Upload
            </Button>
          </div>
        </CardHeader>
        <CardContent className={compact ? "px-3 pb-3 space-y-2" : "space-y-3"}>
          <input
            ref={fileInputRef}
            type="file"
            className="hidden"
            onChange={handleFileSelect}
            data-testid="input-file-upload"
          />

          <div
            className={`border-2 border-dashed rounded-lg p-4 text-center transition-colors cursor-pointer ${
              isDragging ? "border-cyan-400 bg-cyan-500/10" : "border-border/50 hover:border-border hover:bg-muted/30"
            }`}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            role="button"
            tabIndex={0}
            aria-label="Drop zone for file uploads"
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                fileInputRef.current?.click();
              }
            }}
            data-testid="dropzone"
          >
            <Upload className="h-5 w-5 text-muted-foreground mx-auto mb-1.5" />
            <p className="text-xs text-muted-foreground">Drag & drop a file here, or click to browse</p>
            <p className="text-[10px] text-muted-foreground/60 mt-0.5">Max {MAX_FILE_SIZE_LABEL}</p>
          </div>

          {uploadProgress !== null && (
            <div className="space-y-1">
              <div className="flex items-center justify-between text-[10px] text-muted-foreground">
                <span>Uploading...</span>
                <span>{uploadProgress}%</span>
              </div>
              <Progress value={uploadProgress} className="h-1.5" />
            </div>
          )}

          {isLoading ? (
            <div className="space-y-2">
              <Skeleton className="h-9 w-full" />
              <Skeleton className="h-9 w-full" />
              <Skeleton className="h-9 w-full" />
            </div>
          ) : fileCount > 0 ? (
            <div className="space-y-1.5 max-h-64 overflow-y-auto">
              {files!.map((file) => {
                const filename = extractFilename(file.key);
                return (
                  <div
                    key={file.key || file.etag}
                    className="flex items-center gap-2 p-2 rounded-md border border-border/30 bg-muted/10 hover:bg-muted/20 transition-colors group"
                    data-testid={`file-entry-${filename}`}
                  >
                    {getFileIcon(filename)}
                    <div className="min-w-0 flex-1">
                      <p className="text-xs font-medium truncate">{filename}</p>
                      <p className="text-[10px] text-muted-foreground">
                        {formatFileSize(file.size)}
                        {file.lastModified && (
                          <span className="ml-2">{new Date(file.lastModified).toLocaleDateString()}</span>
                        )}
                      </p>
                    </div>
                    <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 w-6 p-0"
                        onClick={(e) => {
                          e.stopPropagation();
                          if (file.key) downloadFile(file.key);
                        }}
                        aria-label={`Download ${filename}`}
                        data-testid={`button-download-${filename}`}
                      >
                        <Download className="h-3 w-3" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 w-6 p-0 text-destructive hover:text-destructive"
                        onClick={(e) => {
                          e.stopPropagation();
                          setDeleteTarget(file);
                        }}
                        aria-label={`Delete ${filename}`}
                        data-testid={`button-delete-${filename}`}
                      >
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-6 text-center">
              <div className="rounded-full bg-muted/30 p-2.5 mb-2">
                <FolderOpen className="h-5 w-5 text-muted-foreground" />
              </div>
              <p className="text-xs text-muted-foreground">No files uploaded yet</p>
              <p className="text-[10px] text-muted-foreground/60 mt-0.5">
                Upload files using the button above or drag & drop
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-destructive">
              <AlertTriangle className="h-4 w-4" />
              Delete File
            </DialogTitle>
            <DialogDescription>
              Are you sure you want to delete{" "}
              <span className="font-mono font-medium text-foreground">{extractFilename(deleteTarget?.key)}</span>? This
              action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" size="sm" onClick={() => setDeleteTarget(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              size="sm"
              onClick={() => {
                if (deleteTarget?.key) deleteMutation.mutate(deleteTarget.key);
              }}
              disabled={deleteMutation.isPending}
              data-testid="button-confirm-delete"
            >
              {deleteMutation.isPending ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
                  Deleting...
                </>
              ) : (
                <>
                  <Trash2 className="h-3.5 w-3.5 mr-1.5" />
                  Delete
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
