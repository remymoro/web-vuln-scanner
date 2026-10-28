import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, effect, inject } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { map } from 'rxjs';
import { ApiClient } from '../../core/api-client';
import { ErrorMessage } from '../../shared/error-message';
import { GradeBadge } from '../../shared/grade-badge';
import { SCAN_STATUS_LABELS } from '../../shared/scan-status';
import { SEVERITY_ORDER, SeverityBadge } from '../../shared/severity-badge';

@Component({
  imports: [DatePipe, RouterLink, ErrorMessage, GradeBadge, SeverityBadge],
  templateUrl: './scan-page.html',
})
export class ScanPage {
  private readonly api = inject(ApiClient);
  private readonly route = inject(ActivatedRoute);
  readonly id = toSignal(this.route.paramMap.pipe(map((params) => params.get('id') ?? undefined)));
  readonly scan = this.api.scan(this.id);
  readonly report = this.api.report(() =>
    this.scan.hasValue() && this.scan.value().status === 'done' ? this.id() : undefined,
  );
  readonly findings = computed(() =>
    this.report.hasValue()
      ? [...this.report.value().findings].sort(
          (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
        )
      : [],
  );
  readonly statusLabels = SCAN_STATUS_LABELS;

  private readonly polling = effect((cleanup) => {
    if (this.scan.isLoading() || !this.id()) return;
    // Réessayer a un sens après une panne serveur ou réseau, jamais après un 4xx (404, 401…).
    const error = this.scan.error();
    if (error instanceof HttpErrorResponse && error.status >= 400 && error.status < 500) return;
    const status = this.scan.hasValue() ? this.scan.value().status : undefined;
    if (status === 'done' || status === 'failed') return;
    const timer = setTimeout(() => this.scan.reload(), 2000);
    cleanup(() => clearTimeout(timer));
  });
}
