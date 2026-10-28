import { ScanStatus } from '../core/api.models';

export const SCAN_STATUS_LABELS: Record<ScanStatus, string> = {
  pending: 'En attente',
  running: 'En cours',
  done: 'Terminé',
  failed: 'Échec',
};
