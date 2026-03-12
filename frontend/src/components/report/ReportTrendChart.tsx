import { useState, useEffect } from "react";
import { TrendingUp, TrendingDown, Minus, Calendar } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ApiClient } from "@/lib/api";
import { cn } from "@/lib/utils";

interface TrendChartProps {
  jobId: string;
  limit?: number;
}

interface TrendData {
  direction: "improving" | "regressing" | "stable" | "insufficient_data";
  score_change: number;
  chart_data: Array<{
    date: string;
    score: number;
    findings: number;
    grade: string;
  }>;
  first_scan?: {
    overall_score: number;
    grade: string;
    total_findings: number;
  };
  last_scan?: {
    overall_score: number;
    grade: string;
    total_findings: number;
  };
}

export function ReportTrendChart({ jobId, limit = 10 }: TrendChartProps) {
  const [trend, setTrend] = useState<TrendData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchTrend = async () => {
      try {
        const data = await ApiClient.getTrends(jobId, limit);
        setTrend(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load trends");
      } finally {
        setLoading(false);
      }
    };

    fetchTrend();
  }, [jobId, limit]);

  if (loading) {
    return (
      <Card className="border-white/10 bg-gradient-to-br from-white/[0.03] to-white/[0.01]">
        <CardContent className="p-6">
          <div className="flex flex-col items-center justify-center gap-3">
            <div className="w-10 h-10 border-2 border-cyan-400/30 border-t-cyan-400 rounded-full animate-spin" />
            <p className="text-sm text-muted-foreground">Loading trend data...</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card className="border-red-500/20 bg-gradient-to-br from-red-500/10 to-red-500/5">
        <CardContent className="p-6 text-center">
          <p className="text-red-400">{error}</p>
        </CardContent>
      </Card>
    );
  }

  if (!trend || trend.direction === "insufficient_data") {
    return (
      <Card className="border-white/10 bg-gradient-to-br from-white/[0.03] to-white/[0.01]">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Calendar className="h-4 w-4 text-cyan-400" />
            Score Trend
          </CardTitle>
        </CardHeader>
        <CardContent className="text-center py-6">
          <div className="w-16 h-16 mx-auto mb-3 rounded-full bg-white/5 flex items-center justify-center">
            <Calendar className="h-6 w-6 text-white/30" />
          </div>
          <p className="text-sm text-white/60">Not enough scan history</p>
          <p className="mt-1 text-xs text-white/40">Run multiple scans to track progress</p>
        </CardContent>
      </Card>
    );
  }

  const getTrendIcon = () => {
    switch (trend.direction) {
      case "improving":
        return <TrendingUp className="h-5 w-5 text-green-400" />;
      case "regressing":
        return <TrendingDown className="h-5 w-5 text-red-400" />;
      default:
        return <Minus className="h-5 w-5 text-yellow-400" />;
    }
  };

  const getTrendColor = () => {
    switch (trend.direction) {
      case "improving":
        return "text-green-400";
      case "regressing":
        return "text-red-400";
      default:
        return "text-yellow-400";
    }
  };

  // Calculate chart dimensions
  const chartWidth = 400;
  const chartHeight = 150;
  const padding = 30;
  const dataPoints = trend.chart_data;

  // Calculate min/max for scaling
  const scores = dataPoints.map((d) => d.score);
  const minScore = Math.max(0, Math.min(...scores) - 10);
  const maxScore = Math.min(100, Math.max(...scores) + 10);
  const scoreRange = maxScore - minScore;

  // Generate SVG path
  const generatePath = () => {
    if (dataPoints.length < 2) return "";

    const xStep = (chartWidth - padding * 2) / (dataPoints.length - 1);

    return dataPoints
      .map((point, i) => {
        const x = padding + i * xStep;
        const y = chartHeight - padding - ((point.score - minScore) / scoreRange) * (chartHeight - padding * 2);
        return `${i === 0 ? "M" : "L"} ${x} ${y}`;
      })
      .join(" ");
  };

  // Generate grid lines
  const gridLines = [0, 25, 50, 75, 100].filter((s) => s >= minScore && s <= maxScore);

  return (
    <Card className="border-white/10 bg-gradient-to-br from-white/[0.03] to-white/[0.01] overflow-hidden">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2 text-base">
            <Calendar className="h-4 w-4 text-cyan-400" />
            Score Trend
          </CardTitle>
          <div className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-white/5">
            {getTrendIcon()}
            <span className={cn("text-sm font-semibold", getTrendColor())}>
              {trend.score_change > 0 ? "+" : ""}
              {trend.score_change.toFixed(1)}
            </span>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Summary Stats */}
        <div className="grid grid-cols-3 gap-2">
          <div className="rounded-xl border border-white/10 bg-gradient-to-br from-white/[0.05] to-transparent p-3 text-center">
            <div className="text-[10px] uppercase tracking-wider text-white/40">First</div>
            <div className="mt-1 text-xl font-bold text-white">{trend.first_scan?.grade || "-"}</div>
            <div className="text-xs text-cyan-400">
              {trend.first_scan?.overall_score.toFixed(0) || 0}%
            </div>
          </div>
          <div className="rounded-xl border border-cyan-400/20 bg-gradient-to-br from-cyan-400/10 to-transparent p-3 text-center">
            <div className="text-[10px] uppercase tracking-wider text-cyan-400/70">Current</div>
            <div className="mt-1 text-xl font-bold text-white">{trend.last_scan?.grade || "-"}</div>
            <div className="text-xs text-cyan-400">
              {trend.last_scan?.overall_score.toFixed(0) || 0}%
            </div>
          </div>
          <div className="rounded-xl border border-white/10 bg-gradient-to-br from-white/[0.05] to-transparent p-3 text-center">
            <div className="text-[10px] uppercase tracking-wider text-white/40">Findings</div>
            <div className="mt-1 text-xl font-bold text-white">{trend.last_scan?.total_findings || 0}</div>
            <div className="text-xs text-emerald-400">
              {(trend.first_scan?.total_findings || 0) - (trend.last_scan?.total_findings || 0) > 0
                ? `-${(trend.first_scan?.total_findings || 0) - (trend.last_scan?.total_findings || 0)}`
                : `+${(trend.last_scan?.total_findings || 0) - (trend.first_scan?.total_findings || 0)}`}
            </div>
          </div>
        </div>

        {/* SVG Chart */}
        <div className="overflow-x-auto">
          <svg width={chartWidth} height={chartHeight} className="mx-auto">
            {/* Background */}
            <rect x="0" y="0" width={chartWidth} height={chartHeight} fill="transparent" />

            {/* Grid lines */}
            {gridLines.map((score) => {
              const y = chartHeight - padding - ((score - minScore) / scoreRange) * (chartHeight - padding * 2);
              return (
                <g key={score}>
                  <line
                    x1={padding}
                    y1={y}
                    x2={chartWidth - padding}
                    y2={y}
                    stroke="rgba(255,255,255,0.1)"
                    strokeDasharray="4 4"
                  />
                  <text
                    x={padding - 5}
                    y={y + 4}
                    textAnchor="end"
                    className="fill-muted-foreground text-[10px]"
                  >
                    {score}
                  </text>
                </g>
              );
            })}

            {/* Gradient fill under line */}
            <defs>
              <linearGradient id="scoreGradient" x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" stopColor="rgba(34, 211, 238, 0.3)" />
                <stop offset="100%" stopColor="rgba(34, 211, 238, 0)" />
              </linearGradient>
            </defs>

            {/* Area fill */}
            {dataPoints.length >= 2 && (
              <path
                d={`${generatePath()} L ${chartWidth - padding} ${chartHeight - padding} L ${padding} ${chartHeight - padding} Z`}
                fill="url(#scoreGradient)"
              />
            )}

            {/* Line */}
            {dataPoints.length >= 2 && (
              <path
                d={generatePath()}
                fill="none"
                stroke="rgba(34, 211, 238, 0.8)"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            )}

            {/* Data points */}
            {dataPoints.map((point, i) => {
              const xStep = (chartWidth - padding * 2) / (dataPoints.length - 1);
              const x = padding + i * xStep;
              const y = chartHeight - padding - ((point.score - minScore) / scoreRange) * (chartHeight - padding * 2);
              return (
                <g key={i}>
                  <circle cx={x} cy={y} r="4" fill="rgba(34, 211, 238, 1)" />
                  <circle cx={x} cy={y} r="6" fill="rgba(34, 211, 238, 0.3)" />
                </g>
              );
            })}
          </svg>
        </div>

        {/* Legend */}
        <div className="flex items-center justify-center gap-4 text-xs text-muted-foreground">
          <span>Score over {dataPoints.length} scans</span>
        </div>
      </CardContent>
    </Card>
  );
}
