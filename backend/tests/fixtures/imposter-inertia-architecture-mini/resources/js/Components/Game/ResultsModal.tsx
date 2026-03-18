export function ResultsModal({ open }: { open: boolean }) {
  if (!open) {
    return null;
  }

  return <aside>results</aside>;
}
