import { useEffect, useMemo, useState } from "react";
import {
  ChevronDown,
  ChevronRight,
  Layers,
  Monitor,
  Server,
  Check,
  AlertCircle,
  Shield,
  Zap,
  Eye,
  Code,
} from "lucide-react";
import { ApiClient, type RuleMetadataResponse } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface AdvancedProfileConfigProps {
  selectedRules: Set<string>;
  onSelectedRulesChange: (rules: Set<string>) => void;
  onBack: () => void;
}

const ICON_MAP: Record<string, React.FC<{ className?: string }>> = {
  Server,
  Monitor,
  Layers,
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-300 border-red-500/30",
  high: "bg-orange-500/20 text-orange-300 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-300 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-300 border-blue-500/30",
};

const SEVERITY_ICONS: Record<string, React.FC<{ className?: string }>> = {
  critical: Shield,
  high: AlertCircle,
  medium: Zap,
  low: Eye,
};

export const AdvancedProfileConfig: React.FC<AdvancedProfileConfigProps> = ({
  selectedRules,
  onSelectedRulesChange,
  onBack,
}) => {
  const [metadata, setMetadata] = useState<RuleMetadataResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [expandedLayers, setExpandedLayers] = useState<Set<string>>(new Set(["backend", "frontend", "shared"]));
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set());

  useEffect(() => {
    ApiClient.getRuleMetadata()
      .then((data) => {
        setMetadata(data);
        // Expand all categories by default
        const allCategories = new Set<string>();
        data.layers.forEach((layer) => {
          layer.categories.forEach((cat) => {
            allCategories.add(`${layer.id}:${cat.id}`);
          });
        });
        setExpandedCategories(allCategories);
      })
      .catch((err) => {
        console.error("Failed to load rule metadata:", err);
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  const stats = useMemo(() => {
    if (!metadata) {
      return { total: 0, selected: 0 };
    }
    let total = 0;
    metadata.layers.forEach((layer) => {
      layer.categories.forEach((cat) => {
        total += cat.rules.length;
      });
    });
    return { total, selected: selectedRules.size };
  }, [metadata, selectedRules]);

  const toggleLayer = (layerId: string) => {
    const newExpanded = new Set(expandedLayers);
    if (newExpanded.has(layerId)) {
      newExpanded.delete(layerId);
    } else {
      newExpanded.add(layerId);
    }
    setExpandedLayers(newExpanded);
  };

  const toggleCategory = (layerId: string, categoryId: string) => {
    const key = `${layerId}:${categoryId}`;
    const newExpanded = new Set(expandedCategories);
    if (newExpanded.has(key)) {
      newExpanded.delete(key);
    } else {
      newExpanded.add(key);
    }
    setExpandedCategories(newExpanded);
  };

  const toggleRule = (ruleId: string) => {
    const newSelected = new Set(selectedRules);
    if (newSelected.has(ruleId)) {
      newSelected.delete(ruleId);
    } else {
      newSelected.add(ruleId);
    }
    onSelectedRulesChange(newSelected);
  };

  const selectAllInCategory = (rules: Array<{ id: string }>, select: boolean) => {
    const newSelected = new Set(selectedRules);
    rules.forEach((rule) => {
      if (select) {
        newSelected.add(rule.id);
      } else {
        newSelected.delete(rule.id);
      }
    });
    onSelectedRulesChange(newSelected);
  };

  const selectAllInLayer = (categories: Array<{ rules: Array<{ id: string }> }>, select: boolean) => {
    const newSelected = new Set(selectedRules);
    categories.forEach((cat) => {
      cat.rules.forEach((rule) => {
        if (select) {
          newSelected.add(rule.id);
        } else {
          newSelected.delete(rule.id);
        }
      });
    });
    onSelectedRulesChange(newSelected);
  };

  const selectAll = () => {
    if (!metadata) return;
    const allRules = new Set<string>();
    metadata.layers.forEach((layer) => {
      layer.categories.forEach((cat) => {
        cat.rules.forEach((rule) => {
          allRules.add(rule.id);
        });
      });
    });
    onSelectedRulesChange(allRules);
  };

  const clearAll = () => {
    onSelectedRulesChange(new Set());
  };

  if (loading) {
    return (
      <div className="flex min-h-[50vh] items-center justify-center">
        <div className="rounded-full border border-white/10 bg-white/[0.04] px-5 py-3 text-sm text-white/70 backdrop-blur-xl">
          Loading rule configuration...
        </div>
      </div>
    );
  }

  if (!metadata) {
    return (
      <div className="flex min-h-[50vh] items-center justify-center">
        <div className="rounded-[1.75rem] border border-red-400/20 bg-red-400/10 px-6 py-5 text-sm text-red-100">
          Failed to load rule metadata.
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      {/* Header */}
      <div className="space-y-4">
        <Button
          variant="ghost"
          onClick={onBack}
          className="w-fit px-0 text-white/65 hover:bg-transparent hover:text-white"
        >
          <ChevronRight className="mr-2 h-4 w-4 rotate-180" />
          Back to profile selection
        </Button>

        <div className="space-y-3">
          <div className="inline-flex items-center gap-2 rounded-full border border-purple-400/20 bg-purple-400/10 px-4 py-2 text-xs font-semibold uppercase tracking-[0.26em] text-purple-100/80">
            <Code className="h-4 w-4" />
            Advanced Configuration
          </div>
          <h2 className="text-3xl font-semibold tracking-tight text-white">
            Select rules for your custom scan
          </h2>
          <p className="max-w-2xl text-base leading-7 text-white/60">
            Fine-tune which rules to run. Rules are grouped by layer (Backend/Frontend) and category.
            Select entire groups or individual rules.
          </p>
        </div>
      </div>

      {/* Stats Bar */}
      <div className="flex flex-wrap items-center gap-4 rounded-[1.5rem] border border-white/10 bg-white/[0.04] px-5 py-4">
        <div className="flex items-center gap-2">
          <div className="h-2.5 w-2.5 rounded-full bg-gradient-to-br from-cyan-400 to-emerald-400 shadow-[0_0_14px_rgba(125,211,252,0.7)]" />
          <span className="text-sm text-white/70">
            <span className="font-semibold text-white">{stats.selected}</span> of {stats.total} rules selected
          </span>
        </div>

        <div className="ml-auto flex gap-2">
          <Button variant="outline" size="sm" onClick={selectAll} className="h-8">
            Select All
          </Button>
          <Button variant="outline" size="sm" onClick={clearAll} className="h-8">
            Clear All
          </Button>
        </div>
      </div>

      {/* Layer Groups */}
      <div className="space-y-4">
        {metadata.layers.map((layer) => {
          const LayerIcon = ICON_MAP[layer.icon] || Layers;
          const isLayerExpanded = expandedLayers.has(layer.id);
          const layerRulesCount = layer.categories.reduce((sum, cat) => sum + cat.rules.length, 0);
          const layerSelectedCount = layer.categories.reduce(
            (sum, cat) => sum + cat.rules.filter((r) => selectedRules.has(r.id)).length,
            0
          );
          const allLayerSelected = layerSelectedCount === layerRulesCount;
          const someLayerSelected = layerSelectedCount > 0 && !allLayerSelected;

          return (
            <div
              key={layer.id}
              className="rounded-[1.75rem] border border-white/10 bg-gradient-to-br from-white/[0.04] to-transparent overflow-hidden"
            >
              {/* Layer Header */}
              <div
                className="flex items-center gap-4 px-5 py-4 cursor-pointer hover:bg-white/[0.02] transition-colors"
                onClick={() => toggleLayer(layer.id)}
              >
                <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-white/10 bg-white/[0.04]">
                  <LayerIcon className="h-5 w-5 text-white/70" />
                </div>

                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    selectAllInLayer(layer.categories, !allLayerSelected);
                  }}
                  className={cn(
                    "flex h-6 w-6 items-center justify-center rounded-md border transition-colors",
                    allLayerSelected
                      ? "border-cyan-400/50 bg-cyan-400/20 text-cyan-300"
                      : someLayerSelected
                        ? "border-cyan-400/30 bg-cyan-400/10"
                        : "border-white/20 hover:border-white/40"
                  )}
                >
                  {allLayerSelected && <Check className="h-4 w-4" />}
                  {someLayerSelected && !allLayerSelected && (
                    <div className="h-2.5 w-2.5 rounded-sm bg-cyan-400" />
                  )}
                </button>

                <div className="flex-1">
                  <div className="text-lg font-semibold text-white">{layer.label}</div>
                  <div className="text-sm text-white/55">{layer.description}</div>
                </div>

                <div className="text-sm text-white/50">
                  {layerSelectedCount}/{layerRulesCount}
                </div>

                <ChevronDown
                  className={cn(
                    "h-5 w-5 text-white/50 transition-transform",
                    !isLayerExpanded && "-rotate-90"
                  )}
                />
              </div>

              {/* Categories */}
              {isLayerExpanded && (
                <div className="border-t border-white/5 px-5 py-4 space-y-3">
                  {layer.categories.map((category) => {
                    const categoryKey = `${layer.id}:${category.id}`;
                    const isCategoryExpanded = expandedCategories.has(categoryKey);
                    const categorySelectedCount = category.rules.filter((r) =>
                      selectedRules.has(r.id)
                    ).length;
                    const allCategorySelected = categorySelectedCount === category.rules.length;
                    const someCategorySelected = categorySelectedCount > 0 && !allCategorySelected;

                    return (
                      <div key={category.id} className="rounded-xl border border-white/8 bg-white/[0.02]">
                        {/* Category Header */}
                        <div
                          className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-white/[0.02] transition-colors"
                          onClick={() => toggleCategory(layer.id, category.id)}
                        >
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              selectAllInCategory(category.rules, !allCategorySelected);
                            }}
                            className={cn(
                              "flex h-5 w-5 items-center justify-center rounded border transition-colors",
                              allCategorySelected
                                ? "border-emerald-400/50 bg-emerald-400/20 text-emerald-300"
                                : someCategorySelected
                                  ? "border-emerald-400/30 bg-emerald-400/10"
                                  : "border-white/20 hover:border-white/40"
                            )}
                          >
                            {allCategorySelected && <Check className="h-3 w-3" />}
                            {someCategorySelected && !allCategorySelected && (
                              <div className="h-1.5 w-1.5 rounded-sm bg-emerald-400" />
                            )}
                          </button>

                          <div className="flex-1">
                            <div className="text-sm font-semibold text-white">{category.label}</div>
                            <div className="text-xs text-white/45">{category.description}</div>
                          </div>

                          <div className="text-xs text-white/40">
                            {categorySelectedCount}/{category.rules.length}
                          </div>

                          <ChevronRight
                            className={cn(
                              "h-4 w-4 text-white/40 transition-transform",
                              isCategoryExpanded && "rotate-90"
                            )}
                          />
                        </div>

                        {/* Rules List */}
                        {isCategoryExpanded && (
                          <div className="border-t border-white/5 px-4 py-3 space-y-2">
                            {category.rules.map((rule) => {
                              const isSelected = selectedRules.has(rule.id);
                              const SeverityIcon = SEVERITY_ICONS[rule.severity] || Eye;

                              return (
                                <div
                                  key={rule.id}
                                  className="flex items-start gap-3 rounded-lg px-3 py-2 hover:bg-white/[0.03] transition-colors"
                                >
                                  <button
                                    type="button"
                                    onClick={() => toggleRule(rule.id)}
                                    className={cn(
                                      "mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded border transition-colors",
                                      isSelected
                                        ? "border-cyan-400/50 bg-cyan-400/20 text-cyan-300"
                                        : "border-white/20 hover:border-white/40"
                                    )}
                                  >
                                    {isSelected && <Check className="h-3 w-3" />}
                                  </button>

                                  <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-2 flex-wrap">
                                      <span className="text-sm font-medium text-white">
                                        {rule.name}
                                      </span>
                                      <span
                                        className={cn(
                                          "inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium border",
                                          SEVERITY_COLORS[rule.severity] || SEVERITY_COLORS.low
                                        )}
                                      >
                                        <SeverityIcon className="h-2.5 w-2.5" />
                                        {rule.severity}
                                      </span>
                                    </div>
                                    <div className="text-xs text-white/50 mt-0.5">
                                      {rule.description}
                                    </div>
                                    {rule.tags.length > 0 && (
                                      <div className="flex gap-1 mt-1 flex-wrap">
                                        {rule.tags.map((tag) => (
                                          <span
                                            key={tag}
                                            className="rounded bg-white/5 px-1.5 py-0.5 text-[10px] text-white/40"
                                          >
                                            {tag}
                                          </span>
                                        ))}
                                      </div>
                                    )}
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Action Bar */}
      <div className="flex items-center justify-between gap-4 rounded-[1.5rem] border border-white/10 bg-white/[0.04] px-5 py-4">
        <div className="text-sm text-white/60">
          {stats.selected === 0 ? (
            <span className="text-amber-300">No rules selected - scan will not run any checks</span>
          ) : stats.selected < 5 ? (
            <span className="text-yellow-300">Very few rules selected - consider adding more for comprehensive analysis</span>
          ) : (
            <span className="text-emerald-300">Ready to scan with {stats.selected} rules</span>
          )}
        </div>

        <Button variant="premium" onClick={onBack} className="h-10 px-6">
          <Check className="mr-2 h-4 w-4" />
          Apply Selection
        </Button>
      </div>
    </div>
  );
};
