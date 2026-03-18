type StagePanelProps = {
  title: string;
  timerLabel: string;
};

export function StagePanel({ title, timerLabel }: StagePanelProps) {
  return (
    <section>
      <h2>{title}</h2>
      <p>{timerLabel}</p>
    </section>
  );
}
