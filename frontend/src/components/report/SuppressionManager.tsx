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
import { Input } from "@/components/ui/input";
import {
  BellOff,
  Plus,
  Trash2,
  Clock,
  Loader2,
  RefreshCw,
  Calendar,
  FileCode,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { ApiClient, type SuppressionListResult } from "@/lib/api";

interface SuppressionManagerProps {
  jobId: string;
}

export function SuppressionManager({ jobId }: SuppressionManagerProps) {
  const [loading, setLoading] = useState(false);
  const [suppressions, setSuppressions] = useState<SuppressionListResult | null>(null);
  const [showAddForm, setShowAddForm] = useState(false);
  const [newFingerprint, setNewFingerprint] = useState("");
  const [newReason, setNewReason] = useState("");
  const [newUntil, setNewUntil] = useState("");
  const [adding, setAdding] = useState(false);
  const [clearing, setClearing] = useState(false);

  const loadSuppressions = async () => {
    setLoading(true);
    try {
      const data = await ApiClient.getSuppressions(jobId);
      setSuppressions(data);
    } catch (err) {
      console.error("Failed to load suppressions:", err);
    } finally {
      setLoading(false);
    }
  };

  const addSuppression = async () => {
    if (!newFingerprint.trim()) return;
    setAdding(true);
    try {
      await ApiClient.addSuppression(jobId, {
        fingerprint: newFingerprint,
        reason: newReason,
        until: newUntil || undefined,
      });
      setNewFingerprint("");
      setNewReason("");
      setNewUntil("");
      setShowAddForm(false);
      loadSuppressions();
    } catch (err) {
      console.error("Failed to add suppression:", err);
    } finally {
      setAdding(false);
    }
  };

  const removeSuppression = async (fingerprint: string) => {
    try {
      await ApiClient.removeSuppression(jobId, fingerprint);
      loadSuppressions();
    } catch (err) {
      console.error("Failed to remove suppression:", err);
    }
  };

  const clearExpired = async () => {
    setClearing(true);
    try {
      await ApiClient.clearExpiredSuppressions(jobId);
      loadSuppressions();
    } catch (err) {
      console.error("Failed to clear expired suppressions:", err);
    } finally {
      setClearing(false);
    }
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return "Never";
    return new Date(dateStr).toLocaleDateString();
  };

  const isExpired = (until: string | null) => {
    if (!until) return false;
    return new Date(until) < new Date();
  };

  return (
    <Card className="bg-slate-900/50 border-slate-700/50">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <BellOff className="h-5 w-5 text-orange-400" />
            <CardTitle className="text-lg">Suppressions</CardTitle>
            {suppressions && suppressions.total > 0 && (
              <Badge variant="secondary" className="ml-2">
                {suppressions.total} active
              </Badge>
            )}
          </div>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={clearExpired}
              disabled={clearing}
            >
              {clearing ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <Clock className="h-4 w-4 mr-1" />
              )}
              Clear Expired
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={loadSuppressions}
              disabled={loading}
            >
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <RefreshCw className="h-4 w-4 mr-1" />
              )}
              Refresh
            </Button>
          </div>
        </div>
        <CardDescription>
          Suppress specific findings to hide them from future scans.
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-3">
        {/* Add suppression form */}
        {showAddForm ? (
          <div className="p-3 bg-slate-800/50 rounded-lg space-y-2">
            <Input
              placeholder="Finding fingerprint"
              value={newFingerprint}
              onChange={(e) => setNewFingerprint(e.target.value)}
              className="bg-slate-900/50 border-slate-600"
            />
            <Input
              placeholder="Reason for suppression"
              value={newReason}
              onChange={(e) => setNewReason(e.target.value)}
              className="bg-slate-900/50 border-slate-600"
            />
            <Input
              type="date"
              placeholder="Until date (optional)"
              value={newUntil}
              onChange={(e) => setNewUntil(e.target.value)}
              className="bg-slate-900/50 border-slate-600"
            />
            <div className="flex gap-2">
              <Button
                size="sm"
                onClick={addSuppression}
                disabled={adding || !newFingerprint.trim()}
              >
                {adding ? (
                  <Loader2 className="h-4 w-4 animate-spin mr-1" />
                ) : (
                  <Plus className="h-4 w-4 mr-1" />
                )}
                Add
              </Button>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => setShowAddForm(false)}
              >
                Cancel
              </Button>
            </div>
          </div>
        ) : (
          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowAddForm(true)}
            className="w-full"
          >
            <Plus className="h-4 w-4 mr-1" />
            Add Suppression
          </Button>
        )}

        {/* Suppression list */}
        {!suppressions && !loading && (
          <div className="text-center py-6 text-slate-400">
            <BellOff className="h-8 w-8 mx-auto mb-2 opacity-50" />
            <p className="text-sm">Click "Refresh" to load suppressions</p>
          </div>
        )}

        {suppressions && suppressions.suppressions.length === 0 && (
          <div className="text-center py-6 text-slate-400">
            <BellOff className="h-8 w-8 mx-auto mb-2 opacity-50" />
            <p className="text-sm">No suppressions configured</p>
          </div>
        )}

        {suppressions && suppressions.suppressions.length > 0 && (
          <div className="space-y-2 max-h-[300px] overflow-y-auto">
            {suppressions.suppressions.map((s) => {
              const expired = isExpired(s.until);
              return (
                <div
                  key={s.fingerprint}
                  className={cn(
                    "flex items-start justify-between p-3 rounded-lg border",
                    expired
                      ? "bg-red-500/5 border-red-500/20"
                      : "bg-slate-800/30 border-slate-700/50"
                  )}
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-sm font-mono truncate">
                        {s.fingerprint.slice(0, 16)}...
                      </span>
                      {expired && (
                        <Badge className="bg-red-500/10 text-red-400 text-xs">
                          Expired
                        </Badge>
                      )}
                    </div>
                    <p className="text-xs text-slate-400 truncate">{s.reason || "No reason provided"}</p>
                    <div className="flex items-center gap-3 mt-1 text-xs text-slate-500">
                      {s.file && (
                        <span className="flex items-center gap-1">
                          <FileCode className="h-3 w-3" />
                          {s.file.split("/").pop()}
                        </span>
                      )}
                      {s.until && (
                        <span className="flex items-center gap-1">
                          <Calendar className="h-3 w-3" />
                          Until {formatDate(s.until)}
                        </span>
                      )}
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => removeSuppression(s.fingerprint)}
                    className="h-8 w-8 p-0 text-red-400 hover:text-red-300"
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
