import { Component, inject, signal } from '@angular/core';
import {
  email,
  form,
  FormField,
  FormRoot,
  maxLength,
  minLength,
  required,
} from '@angular/forms/signals';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { ApiClient } from '../../core/api-client';
import { AuthService } from '../../core/auth-service';
import { ErrorMessage } from '../../shared/error-message';

@Component({
  imports: [FormField, FormRoot, RouterLink, ErrorMessage],
  templateUrl: './auth-page.html',
})
export class AuthPage {
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly api = inject(ApiClient);
  private readonly auth = inject(AuthService);
  readonly registering = this.route.snapshot.data['mode'] === 'register';
  readonly registered = this.route.snapshot.queryParamMap.has('registered');
  readonly error = signal<unknown>(null);
  readonly model = signal({ email: '', password: '' });
  readonly credentials = form(
    this.model,
    (path) => {
      required(path.email, { message: 'Saisissez votre adresse e-mail.' });
      email(path.email, { message: 'Saisissez une adresse e-mail valide.' });
      maxLength(path.email, 320, { message: 'L’adresse e-mail est trop longue.' });
      required(path.password, { message: 'Saisissez votre mot de passe.' });
      minLength(path.password, 12, {
        message: 'Le mot de passe doit contenir au moins 12 caractères.',
      });
      maxLength(path.password, 128, {
        message: 'Le mot de passe doit contenir au plus 128 caractères.',
      });
    },
    {
      submission: {
        action: async () => {
          this.error.set(null);
          try {
            if (this.registering) {
              await firstValueFrom(this.api.register(this.model()));
              await this.router.navigate(['/login'], { queryParams: { registered: '1' } });
            } else {
              await this.auth.login(this.model());
              await this.router.navigateByUrl('/targets');
            }
          } catch (error) {
            this.error.set(error);
          }
        },
      },
    },
  );
}
