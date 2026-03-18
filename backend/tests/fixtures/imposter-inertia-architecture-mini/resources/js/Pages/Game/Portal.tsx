import { VotingBottomPanel } from "../../Components/Game/VotingBottomPanel";
import { ResultsModal } from "../../Components/Game/ResultsModal";
import { useGamePortalState } from "../../hooks/useGamePortalState";
import { adminGameService } from "../../services/adminGame.service";
import type { Player } from "../../types/game";

const players: Player[] = [
  { id: 1, name: "Ada", score: 20 },
  { id: 2, name: "Linus", score: 15 },
];

export default function Portal() {
  const { activePlayer } = useGamePortalState(players);

  return (
    <section data-connected={String(adminGameService.reconnect())}>
      <span>{activePlayer?.name ?? "none"}</span>
      <VotingBottomPanel players={players} />
      <ResultsModal open={false} />
    </section>
  );
}
