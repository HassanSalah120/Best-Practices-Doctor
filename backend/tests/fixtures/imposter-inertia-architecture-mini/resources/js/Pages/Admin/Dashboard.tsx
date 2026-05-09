import { ScorePanel } from "../../Components/Game/ScorePanel";
import { ResultsModal } from "../../Components/Game/ResultsModal";
import { VotingBottomPanel } from "../../Components/Game/VotingBottomPanel";
import { useAdminDashboardState } from "../../hooks/useAdminDashboardState";
import { formatTimer } from "./utils/formatTimer";
import type { Player } from "../../types/game";

const players: Player[] = [
  { id: 1, name: "Ada", score: 20 },
  { id: 2, name: "Linus", score: 15 },
];

export default function Dashboard() {
  const { leaderboard } = useAdminDashboardState(players);

  return (
    <main data-timer={formatTimer(30)}>
      <ScorePanel players={leaderboard} />
      <VotingBottomPanel players={leaderboard} />
      <ResultsModal open={false} />
    </main>
  );
}
