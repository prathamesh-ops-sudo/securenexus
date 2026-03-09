import { usePageTitle } from "@/hooks/use-page-title";
import { FileManager } from "@/components/file-manager";
import { FolderOpen } from "lucide-react";

export default function FileManagerPage() {
  usePageTitle("File Manager");

  return (
    <div className="p-6 space-y-4 animate-fade-in" data-testid="file-manager-page">
      <div>
        <h1 className="text-xl font-bold tracking-tight flex items-center gap-2">
          <FolderOpen className="h-5 w-5 text-cyan-400" />
          <span className="gradient-text-red">File Manager</span>
        </h1>
        <p className="text-sm text-muted-foreground mt-0.5">Upload, browse, and manage org-scoped files and evidence</p>
        <div className="gradient-accent-line w-24 mt-2" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <FileManager prefix="uploads/" title="Uploads" />
        <FileManager prefix="evidence/" title="Evidence" />
      </div>
    </div>
  );
}
