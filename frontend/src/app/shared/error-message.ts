import { Component, computed, effect, input, signal } from '@angular/core';
import { translateApiError } from '../core/api-error';

@Component({
  selector: 'app-error-message',
  template: `
    <div aria-live="polite" aria-atomic="true">
      @if (error()) {
        <p class="error" role="alert">
          {{ translated().message }}
          @if (translated().retryAt !== undefined) {
            @if (remaining() > 0) {
              Réessayez dans {{ remaining() }} s.
            } @else {
              Vous pouvez réessayer.
            }
          }
        </p>
      }
    </div>
  `,
})
export class ErrorMessage {
  readonly error = input<unknown>();
  readonly translated = computed(() => translateApiError(this.error()));
  private readonly now = signal(Date.now());
  readonly remaining = computed(() =>
    Math.max(0, Math.ceil(((this.translated().retryAt ?? 0) - this.now()) / 1000)),
  );

  private readonly countdown = effect((cleanup) => {
    const deadline = this.translated().retryAt;
    if (deadline === undefined) return;
    const tick = () => {
      this.now.set(Date.now());
      if (Date.now() >= deadline) clearInterval(timer);
    };
    this.now.set(Date.now());
    if (deadline <= Date.now()) return;
    const timer = setInterval(tick, 1000);
    cleanup(() => clearInterval(timer));
  });
}
