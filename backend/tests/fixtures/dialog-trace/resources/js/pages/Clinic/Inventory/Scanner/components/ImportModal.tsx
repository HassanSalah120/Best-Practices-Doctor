import Modal from '@/components/UI/Modal';

export function ImportModal({ open, onClose }) {
  return <Modal open={open} onClose={onClose}><div>Import</div></Modal>;
}
