import { buildPortalTitle } from "../../Pages/Game/utils/portalUi";
import type { Player } from "../../types/game";

export function VotingBottomPanel({ players }: { players: Player[] }) {
  return (
    <footer aria-label={buildPortalTitle("vote")}>
      {players.map((player) => (
        <button key={player.id} type="button">
          {player.name}
        </button>
      ))}
    </footer>
  );
}
