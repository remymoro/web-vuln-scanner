import { DatePipe } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { firstValueFrom, map } from 'rxjs';
import { ApiClient } from '../../core/api-client';
import { ErrorMessage } from '../../shared/error-message';
import { GradeBadge } from '../../shared/grade-badge';
import { SCAN_STATUS_LABELS } from '../../shared/scan-status';

@Component({
  imports: [DatePipe, RouterLink, ErrorMessage, GradeBadge],
  templateUrl: './target-page.html',
})
export class TargetPage {
  private readonly api = inject(ApiClient);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  readonly id = toSignal(this.route.paramMap.pipe(map((params) => params.get('id') ?? undefined)));
  readonly target = this.api.target(this.id);
  readonly history = this.api.targetScans(this.id);
  readonly error = signal<unknown>(null);
  readonly busy = signal(false);
  readonly copyMessage = signal('');
  readonly statusLabels = SCAN_STATUS_LABELS;

  async copyRecord() {
    if (!this.target.hasValue()) return;
    try {
      await navigator.clipboard.writeText(this.target.value().dns_record.value);
      this.copyMessage.set('Valeur TXT copiée.');
    } catch {
      this.copyMessage.set('Copie impossible. Sélectionnez et copiez la valeur TXT ci-dessus.');
    }
  }

  async verify() {
    if (!this.id() || this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    try {
      const target = await firstValueFrom(this.api.verifyTarget(this.id()!));
      this.target.set(target);
    } catch (error) {
      this.error.set(error);
    } finally {
      this.busy.set(false);
    }
  }

  async launchScan() {
    if (!this.target.hasValue() || !this.target.value().verified || this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    try {
      const scan = await firstValueFrom(this.api.requestScan(this.id()!));
      await this.router.navigate(['/scans', scan.id]);
    } catch (error) {
      this.error.set(error);
      this.history.reload();
    } finally {
      this.busy.set(false);
    }
  }
}
