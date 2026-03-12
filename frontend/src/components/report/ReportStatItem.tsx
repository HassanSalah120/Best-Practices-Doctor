import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

export function ReportStatItem({
  label,
  value,
  icon,
  variant,
}: {
  label: string;
  value: number | string;
  icon?: ReactNode;
  variant?: string;
}) {
  return (
    <div className="rounded-lg border border-white/5 bg-white/5 p-3">
      <div className="mb-1 flex items-center gap-1.5 text-xs text-muted-foreground">
        {icon}
        {label}
      </div>
      <div
        className={cn(
          "text-xl font-bold",
          variant === "critical" ? "text-red-400" : variant === "high" ? "text-orange-400" : "text-white",
        )}
      >
        {value}
      </div>
    </div>
  );
}
