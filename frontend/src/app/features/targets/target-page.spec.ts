import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, convertToParamMap, provideRouter } from '@angular/router';
import { of } from 'rxjs';
import { TargetPage } from './target-page';

const target = {
  id: 'target',
  domain: 'demo.scanner.test',
  verified: false,
  verified_at: null,
  dns_record: { type: 'TXT', name: 'demo.scanner.test', value: 'scanner-verify=abc' },
};

beforeEach(() =>
  TestBed.configureTestingModule({
    providers: [
      provideHttpClient(),
      provideHttpClientTesting(),
      provideRouter([]),
      { provide: ActivatedRoute, useValue: { paramMap: of(convertToParamMap({ id: 'target' })) } },
    ],
  }),
);
afterEach(() => TestBed.inject(HttpTestingController).verify());

async function setup(history: unknown[] = []) {
  const fixture = TestBed.createComponent(TargetPage);
  fixture.detectChanges();
  const http = TestBed.inject(HttpTestingController);
  http.expectOne('/api/targets/target').flush(target);
  http.expectOne('/api/targets/target/scans').flush(history);
  await fixture.whenStable();
  fixture.detectChanges();
  return { fixture, page: fixture.componentInstance, http };
}

it('affiche le TXT, désactive le scan puis active le bouton après vérification', async () => {
  const { fixture, page, http } = await setup();
  expect(fixture.nativeElement.textContent).toContain('scanner-verify=abc');
  expect(fixture.nativeElement.textContent).toContain('Aucun scan');
  const button = () =>
    [...(fixture.nativeElement.querySelectorAll('button') as NodeListOf<HTMLButtonElement>)].find(
      (item) => item.textContent?.includes('Lancer un scan'),
    )!;
  expect(button().disabled).toBe(true);
  const result = page.verify();
  http.expectOne('/api/targets/target/verify').flush({ ...target, verified: true });
  await result;
  fixture.detectChanges();
  expect(button().disabled).toBe(false);
  expect(fixture.nativeElement.textContent).toContain('Propriété vérifiée');
});

it('affiche les informations DNS dans le message d’échec', async () => {
  const { fixture, page, http } = await setup();
  const result = page.verify();
  http
    .expectOne('/api/targets/target/verify')
    .flush(
      { detail: 'Expected TXT record at demo.scanner.test: scanner-verify=abc' },
      { status: 400, statusText: 'Bad Request' },
    );
  await result;
  fixture.detectChanges();
  expect(fixture.nativeElement.querySelector('.error').textContent).toContain('demo.scanner.test');
  expect(fixture.nativeElement.querySelector('.error').textContent).toContain('scanner-verify=abc');
});

it('copie la valeur TXT et confirme la copie', async () => {
  const { fixture, page } = await setup();
  const writeText = vi.fn().mockResolvedValue(undefined);
  vi.stubGlobal('navigator', { clipboard: { writeText } });
  try {
    await page.copyRecord();
    fixture.detectChanges();
    expect(writeText).toHaveBeenCalledWith('scanner-verify=abc');
    expect(fixture.nativeElement.textContent).toContain('Valeur TXT copiée');
  } finally {
    vi.unstubAllGlobals();
  }
});

it('affiche un scan historique avec son état, sa note et le lien de suivi', async () => {
  const { fixture } = await setup([
    {
      id: 'old-scan',
      status: 'done',
      created_at: '2026-01-01T12:00:00Z',
      grade: 'D',
    },
  ]);
  expect(fixture.nativeElement.querySelector('a[href="/scans/old-scan"]')).toBeTruthy();
  expect(fixture.nativeElement.textContent).toContain('Terminé');
  expect(fixture.nativeElement.querySelector('[aria-label="Note D"]')).toBeTruthy();
});
