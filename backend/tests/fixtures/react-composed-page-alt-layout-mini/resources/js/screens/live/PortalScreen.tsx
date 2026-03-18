import { Head } from "@inertiajs/react";
import { usePortalScreenState } from "../../composables/usePortalScreenState";
import { ResultsDrawer } from "../../widgets/game/ResultsDrawer";
import { StagePanel } from "../../widgets/game/StagePanel";
import { buildPortalLabel } from "./helpers/portalLabels";
import { formatPortalTimer } from "./lib/portalTimer";

export default function PortalScreen() {
  const state = usePortalScreenState();

  return (
    <main data-screen="portal">
      <Head title="Portal" />
      <h1>{buildPortalLabel(state.stageName)}</h1>
      <StagePanel title={state.stageName} timerLabel={formatPortalTimer(30)} />
      <ResultsDrawer open={state.resultsOpen} />
      <footer>{state.timerLabel}</footer>
    </main>
  );
}
