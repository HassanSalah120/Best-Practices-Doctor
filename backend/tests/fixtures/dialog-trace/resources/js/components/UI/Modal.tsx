export default function Modal({ children }) {
  return <div role="dialog" aria-modal="true">{children}</div>;
}

export function ConfirmDialog(props) {
  return <Modal {...props} />;
}
