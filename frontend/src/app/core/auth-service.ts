import { computed, inject, Injectable, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { ApiClient } from './api-client';
import { Credentials } from './api.models';

export const TOKEN_KEY = 'scanner.access_token';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly api = inject(ApiClient);
  private readonly tokenState = signal(sessionStorage.getItem(TOKEN_KEY));
  readonly token = this.tokenState.asReadonly();
  readonly authenticated = computed(() => this.token() !== null);

  async login(credentials: Credentials) {
    const response = await firstValueFrom(this.api.login(credentials));
    sessionStorage.setItem(TOKEN_KEY, response.access_token);
    this.tokenState.set(response.access_token);
  }

  logout() {
    sessionStorage.removeItem(TOKEN_KEY);
    this.tokenState.set(null);
  }
}
