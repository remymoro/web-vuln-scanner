import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, convertToParamMap, provideRouter } from '@angular/router';
import { of } from 'rxjs';
import { ScanPage } from './scan-page';

const scan = {
  id: 'scan',
  target_id: 'target',
  status: 'pending',
  created_at: '2026-01-01T12:00:00Z',
  started_at: null,
  finished_at: null,
  score: null,
  grade: null,
  error: null,
};
const finding = {
  id: 'rule',
  scanner: 'headers',
  category: 'headers',
  description: 'Description',
  evidence: '<script>preuve</script>',
  recommendation: 'Corriger',
};

beforeEach(() =>
  TestBed.configureTestingModule({
    providers: [
      provideHttpClient(),
      provideHttpClientTesting(),
      provideRouter([]),
      { provide: ActivatedRoute, useValue: { paramMap: of(convertToParamMap({ id: 'scan' })) } },
    ],
  }),
);
afterEach(() => TestBed.inject(HttpTestingController).verify());

it('affiche le rapport, ses catégories et les constats triés sans interpréter la preuve HTML', async () => {
  const fixture = TestBed.createComponent(ScanPage);
  fixture.detectChanges();
  const http = TestBed.inject(HttpTestingController);
  http.expectOne('/api/scans/scan').flush({ ...scan, status: 'done' });
  await Promise.resolve();
  TestBed.tick();
  http.expectOne('/api/scans/scan/report').flush({
    score: 48,
    grade: 'D',
    deductions: [],
    categories: [{ category: 'headers', score: 48, grade: 'D', deductions: [] }],
    findings: [
      { ...finding, severity: 'info', title: 'Information' },
      { ...finding, severity: 'high', title: 'Urgent' },
      { ...finding, severity: 'medium', title: 'Moyen' },
    ],
  });
  await fixture.whenStable();
  fixture.detectChanges();
  expect(fixture.nativeElement.textContent).toContain('Terminé');
  expect(fixture.nativeElement.querySelector('[data-testid="report-grade"]').textContent).toContain(
    'D',
  );
  expect(fixture.nativeElement.textContent).toContain('48');
  const titles = [
    ...(fixture.nativeElement.querySelectorAll('article h3') as NodeListOf<HTMLElement>),
  ].map((item) => item.textContent);
  expect(titles).toEqual(['Urgent', 'Moyen', 'Information']);
  expect(fixture.nativeElement.querySelector('pre').textContent).toBe('<script>preuve</script>');
  expect(fixture.nativeElement.querySelector('pre script')).toBeNull();
});

it('affiche le motif d’échec sans demander de rapport', async () => {
  const fixture = TestBed.createComponent(ScanPage);
  fixture.detectChanges();
  const http = TestBed.inject(HttpTestingController);
  http.expectOne('/api/scans/scan').flush({ ...scan, status: 'failed', error: 'timeout' });
  await fixture.whenStable();
  fixture.detectChanges();
  expect(fixture.nativeElement.textContent).toContain('Motif : timeout');
  http.expectNone('/api/scans/scan/report');
});

it.each(['done', 'failed'])('actualise à 2 secondes et arrête le suivi à %s', async (terminal) => {
  const fixture = TestBed.createComponent(ScanPage);
  fixture.detectChanges();
  const http = TestBed.inject(HttpTestingController);
  vi.useFakeTimers();
  try {
    http.expectOne('/api/scans/scan').flush(scan);
    await Promise.resolve();
    TestBed.tick();
    expect(fixture.nativeElement.textContent).toContain('En attente');
    await vi.advanceTimersByTimeAsync(2000);
    TestBed.tick();
    http.expectOne('/api/scans/scan').flush({ ...scan, status: 'running' });
    await Promise.resolve();
    TestBed.tick();
    expect(fixture.nativeElement.textContent).toContain('En cours');
    await vi.advanceTimersByTimeAsync(2000);
    TestBed.tick();
    http
      .expectOne('/api/scans/scan')
      .flush({ ...scan, status: terminal, error: terminal === 'failed' ? 'timeout' : null });
    await Promise.resolve();
    TestBed.tick();
    if (terminal === 'done') {
      http
        .expectOne('/api/scans/scan/report')
        .flush({ score: 100, grade: 'A', categories: [], deductions: [], findings: [] });
      await Promise.resolve();
      TestBed.tick();
    }
    await vi.advanceTimersByTimeAsync(6000);
    TestBed.tick();
    http.expectNone('/api/scans/scan');
  } finally {
    fixture.destroy();
    vi.useRealTimers();
  }
});

it('annule le prochain rafraîchissement à la destruction', async () => {
  const fixture = TestBed.createComponent(ScanPage);
  fixture.detectChanges();
  const http = TestBed.inject(HttpTestingController);
  vi.useFakeTimers();
  try {
    http.expectOne('/api/scans/scan').flush(scan);
    await Promise.resolve();
    TestBed.tick();
    fixture.destroy();
    await vi.advanceTimersByTimeAsync(4000);
    http.expectNone('/api/scans/scan');
  } finally {
    vi.useRealTimers();
  }
});

it('réessaie après une indisponibilité réseau', async () => {
  const fixture = TestBed.createComponent(ScanPage);
  fixture.detectChanges();
  const http = TestBed.inject(HttpTestingController);
  vi.useFakeTimers();
  try {
    http.expectOne('/api/scans/scan').flush({}, { status: 503, statusText: 'Unavailable' });
    await Promise.resolve();
    TestBed.tick();
    expect(fixture.nativeElement.textContent).toContain('temporairement indisponible');
    await vi.advanceTimersByTimeAsync(2000);
    TestBed.tick();
    http.expectOne('/api/scans/scan').flush({ ...scan, status: 'failed', error: 'timeout' });
    await Promise.resolve();
    TestBed.tick();
    expect(fixture.nativeElement.textContent).toContain('Motif : timeout');
  } finally {
    fixture.destroy();
    vi.useRealTimers();
  }
});

it('n’insiste pas après un scan introuvable', async () => {
  const fixture = TestBed.createComponent(ScanPage);
  fixture.detectChanges();
  const http = TestBed.inject(HttpTestingController);
  vi.useFakeTimers();
  try {
    http.expectOne('/api/scans/scan').flush({}, { status: 404, statusText: 'Not Found' });
    await Promise.resolve();
    TestBed.tick();
    await vi.advanceTimersByTimeAsync(10000);
    TestBed.tick();
    http.expectNone('/api/scans/scan');
  } finally {
    fixture.destroy();
    vi.useRealTimers();
  }
});
