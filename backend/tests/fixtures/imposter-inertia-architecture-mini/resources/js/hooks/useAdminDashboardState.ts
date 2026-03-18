import { useMemo, useState } from "react";
import type { Player } from "../types/game";

export function useAdminDashboardState(players: Player[]) {
  const [selectedId, setSelectedId] = useState<number | null>(null);

  const leaderboard = useMemo(
    () => [...players].sort((left, right) => right.score - left.score),
    [players],
  );

  return { leaderboard, selectedId, setSelectedId };
}
