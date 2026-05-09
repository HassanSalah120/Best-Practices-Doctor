import { useMemo, useState } from "react";
import type { Player } from "../types/game";

export function useGamePortalState(players: Player[]) {
  const [activePlayerId, setActivePlayerId] = useState<number | null>(null);

  const activePlayer = useMemo(
    () => players.find((player) => player.id === activePlayerId) ?? null,
    [activePlayerId, players],
  );

  return { activePlayer, activePlayerId, setActivePlayerId };
}
