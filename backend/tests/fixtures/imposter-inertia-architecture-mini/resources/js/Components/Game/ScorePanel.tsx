import type { Player } from "../../types/game";

export function ScorePanel({ players }: { players: Player[] }) {
  return (
    <section>
      {players.map((player) => (
        <div key={player.id}>{player.name}</div>
      ))}
    </section>
  );
}
