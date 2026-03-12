import { cn } from "@/lib/utils";

export function ReportScoreBar({
  label,
  value,
  counted = true,
  tooltip,
}: {
  label: string;
  value: number | null;
  counted?: boolean;
  tooltip?: string;
}) {
  const isNA = value === null || counted === false;
  const numericValue = !isNA && typeof value === "number" && Number.isFinite(value) ? value : 0;
  const color =
    numericValue >= 90
      ? "from-emerald-500 to-emerald-300"
      : numericValue >= 75
        ? "from-sky-500 to-sky-300"
        : numericValue >= 60
          ? "from-yellow-500 to-yellow-300"
          : "from-red-500 to-red-300";

  return (
    <div
      className={cn("rounded-lg border border-white/5 bg-white/5 p-3", isNA ? "opacity-60" : "")}
      title={tooltip || (isNA ? "Category not included in scoring weights" : undefined)}
    >
      <div className="flex items-center justify-between">
        <div className="text-sm font-semibold text-white/80">{label}</div>
        <div className="text-sm font-bold text-white">{isNA ? "N/A" : `${Math.round(numericValue)}%`}</div>
      </div>
      <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-slate-900/60">
        {isNA ? (
          <div className="h-full bg-white/10" style={{ width: "100%" }} />
        ) : (
          <div
            className={cn("h-full bg-gradient-to-r", color)}
            style={{ width: `${Math.max(0, Math.min(100, numericValue))}%` }}
          />
        )}
      </div>
    </div>
  );
}
