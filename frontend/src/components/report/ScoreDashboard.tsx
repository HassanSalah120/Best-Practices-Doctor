import { cn } from "@/lib/utils";
import type { ScanScore } from "@/types/api";
import { Card, CardContent } from "@/components/ui/card";

function scoreTone(score: number): string {
    if (score >= 90) return "border-emerald-400/30 bg-emerald-400/10 text-emerald-100";
    if (score >= 70) return "border-amber-400/30 bg-amber-400/10 text-amber-100";
    if (score >= 50) return "border-orange-400/30 bg-orange-400/10 text-orange-100";
    return "border-red-400/30 bg-red-400/10 text-red-100";
}

const CATEGORIES: Array<{ key: keyof Omit<ScanScore, "overall">; label: string }> = [
    { key: "security", label: "Security" },
    { key: "performance", label: "Performance" },
    { key: "architecture", label: "Architecture" },
    { key: "quality", label: "Quality" },
    { key: "accessibility", label: "Accessibility" },
];

export function ScoreDashboard({ score }: { score: ScanScore }) {
    return (
        <Card className="border-white/10 bg-white/[0.03]">
            <CardContent className="grid gap-4 p-4 lg:grid-cols-[13rem_1fr]">
                <div className={cn("flex items-center gap-4 rounded-xl border p-4", scoreTone(score.overall))}>
                    <div
                        className="grid h-20 w-20 place-items-center rounded-full border-8 border-current/30 bg-slate-950/40 text-3xl font-black"
                        title="Rule-weighted overall score"
                    >
                        {score.overall}
                    </div>
                    <div>
                        <div className="text-sm font-semibold uppercase tracking-[0.18em] opacity-75">Overall</div>
                        <div className="text-xs opacity-70">Rule-weighted score</div>
                    </div>
                </div>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-5">
                    {CATEGORIES.map((item) => {
                        const value = Number(score[item.key] ?? 100);
                        return (
                            <div key={item.key} className={cn("rounded-xl border p-3", scoreTone(value))}>
                                <div className="flex items-center justify-between gap-2">
                                    <span className="text-xs font-semibold uppercase tracking-[0.16em] opacity-75">{item.label}</span>
                                    <span className="text-xl font-bold">{value}</span>
                                </div>
                                <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/10">
                                    <div className="h-full rounded-full bg-current" style={{ width: `${Math.max(0, Math.min(100, value))}%` }} />
                                </div>
                            </div>
                        );
                    })}
                </div>
            </CardContent>
        </Card>
    );
}
