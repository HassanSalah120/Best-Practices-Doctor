type ResultsDrawerProps = {
  open: boolean;
};

export function ResultsDrawer({ open }: ResultsDrawerProps) {
  if (!open) {
    return null;
  }

  return <aside>results</aside>;
}
