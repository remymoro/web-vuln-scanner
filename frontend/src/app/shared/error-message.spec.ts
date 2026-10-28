import { HttpErrorResponse, HttpHeaders } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';
import { ErrorMessage } from './error-message';

it('décompte Retry-After et nettoie le temporisateur', () => {
  vi.useFakeTimers();
  try {
    const fixture = TestBed.createComponent(ErrorMessage);
    fixture.componentRef.setInput(
      'error',
      new HttpErrorResponse({
        status: 429,
        headers: new HttpHeaders({ 'Retry-After': '2' }),
      }),
    );
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('dans 2 s');
    vi.advanceTimersByTime(1000);
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('dans 1 s');
    vi.advanceTimersByTime(1000);
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Vous pouvez réessayer');
    fixture.destroy();
    expect(vi.getTimerCount()).toBe(0);
  } finally {
    vi.useRealTimers();
  }
});
