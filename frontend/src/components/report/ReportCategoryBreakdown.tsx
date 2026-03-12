import { useMemo } from "react";
import { PieChart } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { Finding } from "@/types/api";

interface CategoryBreakdownProps {
  findings: Finding[];
}

// Category colors matching the app theme
const CATEGORY_COLORS: Record<string, string> = {
  security: "#ef4444",      // red
  architecture: "#f59e0b",  // amber
  performance: "#10b981",   // emerald
  complexity: "#3b82f6",    // blue
  maintainability: "#8b5cf6", // violet
  laravel_best_practice: "#ec4899", // pink
  react_best_practice: "#06b6d4", // cyan
  dry: "#84cc16",          // lime
  srp: "#f97316",          // orange
  validation: "#a855f7",    // purple
  accessibility: "#14b8a6", // teal
};

const CATEGORY_LABELS: Record<string, string> = {
  security: "Security",
  architecture: "Architecture",
  performance: "Performance",
  complexity: "Complexity",
  maintainability: "Maintainability",
  laravel_best_practice: "Laravel",
  react_best_practice: "React",
  dry: "DRY",
  srp: "SRP",
  validation: "Validation",
  accessibility: "Accessibility",
};

// Helper function to convert polar to cartesian coordinates
const polarToCartesian = (centerX: number, centerY: number, radius: number, angleInDegrees: number) => {
  const angleInRadians = (angleInDegrees - 90) * Math.PI / 180.0;
  return {
    x: centerX + (radius * Math.cos(angleInRadians)),
    y: centerY + (radius * Math.sin(angleInRadians)),
  };
};

// Helper function to describe an SVG arc path
const describeArc = (x: number, y: number, radius: number, startAngle: number, endAngle: number): string => {
  const start = polarToCartesian(x, y, radius, endAngle);
  const end = polarToCartesian(x, y, radius, startAngle);
  const largeArcFlag = endAngle - startAngle <= 180 ? 0 : 1;

  return [
    "M", x, y,
    "L", start.x, start.y,
    "A", radius, radius, 0, largeArcFlag, 0, end.x, end.y,
    "Z",
  ].join(" ");
};

export function ReportCategoryBreakdown({ findings }: CategoryBreakdownProps) {
  const chartData = useMemo(() => {
    const counts: Record<string, number> = {};

    for (const finding of findings) {
      const category = String(finding.category).toLowerCase();
      counts[category] = (counts[category] || 0) + 1;
    }

    return Object.entries(counts)
      .map(([category, count]) => ({
        name: CATEGORY_LABELS[category] || category,
        category,
        value: count,
        color: CATEGORY_COLORS[category] || "#6b7280",
      }))
      .sort((a, b) => b.value - a.value);
  }, [findings]);

  const totalFindings = findings.length;

  // Calculate pie chart segments
  const pieSegments = useMemo(() => {
    if (chartData.length === 0 || totalFindings === 0) return [];

    const segments: Array<{
      category: string;
      name: string;
      value: number;
      color: string;
      startAngle: number;
      endAngle: number;
    }> = [];

    let currentAngle = 0;

    for (const item of chartData) {
      const angle = (item.value / totalFindings) * 360;
      segments.push({
        ...item,
        startAngle: currentAngle,
        endAngle: currentAngle + angle,
      });
      currentAngle += angle;
    }

    return segments;
  }, [chartData, totalFindings]);

  if (chartData.length === 0) {
    return (
      <Card className="border-white/10 bg-gradient-to-br from-white/[0.03] to-white/[0.01]">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <PieChart className="h-4 w-4 text-cyan-400" />
            Category Breakdown
          </CardTitle>
        </CardHeader>
        <CardContent className="text-center py-6">
          <div className="w-16 h-16 mx-auto mb-3 rounded-full bg-white/5 flex items-center justify-center">
            <PieChart className="h-6 w-6 text-white/30" />
          </div>
          <p className="text-sm text-white/60">No findings to display</p>
        </CardContent>
      </Card>
    );
  }

  const centerX = 100;
  const centerY = 100;
  const radius = 80;

  return (
    <Card className="border-white/10 bg-gradient-to-br from-white/[0.03] to-white/[0.01] overflow-hidden">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-base">
          <PieChart className="h-4 w-4 text-cyan-400" />
          Category Breakdown
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex flex-col gap-4">
          {/* SVG Pie Chart */}
          <div className="flex justify-center">
            <svg width="200" height="200" viewBox="0 0 200 200" className="drop-shadow-lg">
              {/* Background circle */}
              <circle
                cx={centerX}
                cy={centerY}
                r={radius}
                fill="rgba(255,255,255,0.03)"
                stroke="rgba(255,255,255,0.08)"
                strokeWidth="1"
              />
              
              {/* Pie segments */}
              {pieSegments.map((segment, index) => (
                <path
                  key={index}
                  d={describeArc(centerX, centerY, radius, segment.startAngle, segment.endAngle)}
                  fill={segment.color}
                  stroke="rgba(0,0,0,0.2)"
                  strokeWidth="1"
                  className="transition-all duration-200 hover:opacity-90 cursor-pointer"
                  style={{ filter: 'drop-shadow(0 2px 4px rgba(0,0,0,0.3))' }}
                >
                  <title>{`${segment.name}: ${segment.value} (${((segment.value / totalFindings) * 100).toFixed(1)}%)`}</title>
                </path>
              ))}

              {/* Center hole for donut effect */}
              <circle
                cx={centerX}
                cy={centerY}
                r={40}
                fill="rgb(15, 23, 42)"
                stroke="rgba(255,255,255,0.1)"
                strokeWidth="1"
              />

              {/* Center text */}
              <text
                x={centerX}
                y={centerY - 5}
                textAnchor="middle"
                className="fill-white font-bold"
                style={{ fontSize: "24px", fontWeight: 700 }}
              >
                {totalFindings}
              </text>
              <text
                x={centerX}
                y={centerY + 15}
                textAnchor="middle"
                className="fill-slate-400"
                style={{ fontSize: "10px" }}
              >
                findings
              </text>
            </svg>
          </div>

          {/* Legend */}
          <div className="grid grid-cols-2 gap-1.5">
            {chartData.map((item) => {
              const percentage = ((item.value / totalFindings) * 100).toFixed(0);
              return (
                <div
                  key={item.category}
                  className="flex items-center justify-between rounded-lg border border-white/10 bg-white/[0.03] px-2.5 py-1.5 transition-colors hover:bg-white/[0.06]"
                >
                  <div className="flex items-center gap-1.5">
                    <div
                      className="h-2.5 w-2.5 rounded-full shadow-sm"
                      style={{ backgroundColor: item.color }}
                    />
                    <span className="text-xs text-white/80">{item.name}</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <span className="text-xs font-semibold text-white">{item.value}</span>
                    <span className="text-[10px] text-white/40">({percentage}%)</span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Total */}
          <div className="text-center text-xs text-white/40 pt-1">
            {totalFindings} findings across {chartData.length} categories
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
