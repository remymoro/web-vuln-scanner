import { Component, inject, signal } from '@angular/core';
import { form, FormField, FormRoot, required } from '@angular/forms/signals';
import { Router, RouterLink } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { ApiClient } from '../../core/api-client';
import { ErrorMessage } from '../../shared/error-message';

@Component({
  imports: [FormField, FormRoot, RouterLink, ErrorMessage],
  templateUrl: './targets-page.html',
})
export class TargetsPage {
  private readonly api = inject(ApiClient);
  private readonly router = inject(Router);
  readonly targets = this.api.targets();
  readonly error = signal<unknown>(null);
  readonly model = signal({ url: '' });
  readonly declaration = form(
    this.model,
    (path) => {
      required(path.url, { message: 'Saisissez le domaine ou l’URL du site.' });
    },
    {
      submission: {
        action: async () => {
          this.error.set(null);
          try {
            const target = await firstValueFrom(this.api.declareTarget(this.model().url.trim()));
            await this.router.navigate(['/targets', target.id]);
          } catch (error) {
            this.error.set(error);
          }
        },
      },
    },
  );
}
