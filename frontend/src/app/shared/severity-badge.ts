import { Component, input } from '@angular/core';
import { Severity } from '../core/api.models';

export const SEVERITY_ORDER: Record<Severity, number> = { high: 0, medium: 1, low: 2, info: 3 };

@Component({
  selector: 'app-severity-badge',
  template: `<span [class]="'badge severity-' + severity()">{{ labels[severity()] }}</span>`,
})
export class SeverityBadge {
  readonly severity = input.required<Severity>();
  readonly labels: Record<Severity, string> = {
    high: 'Élevée',
    medium: 'Moyenne',
    low: 'Faible',
    info: 'Information',
  };
}
