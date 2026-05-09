import { Head } from "@inertiajs/react";
import { useMatchFilters } from "../../../composables/useMatchFilters";
import { formatDuration } from "../../../lib/date/formatDuration";
import { StatCard } from "../../../widgets/common/StatCard";
import { buildChartLabel } from "./helpers/chartLabel";
import { buildAnalyticsSummary } from "./lib/summaryBuilder";

export default function AnalyticsScreen() {
  const filters = useMatchFilters();

  return (
    <section>
      <Head title="Analytics" />
      <StatCard label={filters.status} value={buildAnalyticsSummary(4)} />
      <span>{buildChartLabel(filters.status)}</span>
      <p>{formatDuration(45)}</p>
    </section>
  );
}
