import { useState } from "react";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  FileJson,
  Download,
  Loader2,
  CheckCircle2,
  ExternalLink,
} from "lucide-react";
import { ApiClient } from "@/lib/api";

interface SarifExportPanelProps {
  jobId: string;
}

export function SarifExportPanel({ jobId }: SarifExportPanelProps) {
  const [exporting, setExporting] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [exported, setExported] = useState(false);
  const [downloaded, setDownloaded] = useState(false);

  const handleExport = async () => {
    setExporting(true);
    try {
      await ApiClient.exportSarif(jobId);
      setExported(true);
    } catch (err) {
      console.error("Failed to export SARIF:", err);
    } finally {
      setExporting(false);
    }
  };

  const handleDownload = async () => {
    setDownloading(true);
    try {
      await ApiClient.downloadSarif(jobId);
      setDownloaded(true);
    } catch (err) {
      console.error("Failed to download SARIF:", err);
    } finally {
      setDownloading(false);
    }
  };

  return (
    <Card className="bg-slate-900/50 border-slate-700/50">
      <CardHeader className="pb-3">
        <div className="flex items-center gap-2">
          <FileJson className="h-5 w-5 text-emerald-400" />
          <CardTitle className="text-lg">SARIF Export</CardTitle>
        </div>
        <CardDescription>
          Export findings in SARIF format for CI/CD integration and code scanning tools.
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-3">
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleExport}
            disabled={exporting}
            className="flex-1"
          >
            {exporting ? (
              <Loader2 className="h-4 w-4 animate-spin mr-1" />
            ) : exported ? (
              <CheckCircle2 className="h-4 w-4 mr-1 text-green-400" />
            ) : (
              <ExternalLink className="h-4 w-4 mr-1" />
            )}
            {exported ? "Exported" : "Export"}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleDownload}
            disabled={downloading}
            className="flex-1"
          >
            {downloading ? (
              <Loader2 className="h-4 w-4 animate-spin mr-1" />
            ) : downloaded ? (
              <CheckCircle2 className="h-4 w-4 mr-1 text-green-400" />
            ) : (
              <Download className="h-4 w-4 mr-1" />
            )}
            {downloaded ? "Downloaded" : "Download"}
          </Button>
        </div>

        <div className="p-3 bg-slate-800/30 rounded-md">
          <h4 className="text-sm font-medium text-slate-300 mb-2">Compatible with:</h4>
          <div className="flex flex-wrap gap-1">
            {["GitHub Code Scanning", "Azure DevOps", "SonarQube", "GitLab"].map((tool) => (
              <Badge key={tool} variant="secondary" className="text-xs">
                {tool}
              </Badge>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
