import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { TargetsPage } from './targets-page';

beforeEach(() =>
  TestBed.configureTestingModule({
    providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
  }),
);
afterEach(() => TestBed.inject(HttpTestingController).verify());

it('affiche le chargement, la liste vide puis les sites et leur vérification', async () => {
  const fixture = TestBed.createComponent(TargetsPage);
  fixture.detectChanges();
  const http = TestBed.inject(HttpTestingController);
  expect(fixture.nativeElement.textContent).toContain('Chargement des sites');
  http.expectOne('/api/targets').flush([]);
  await fixture.whenStable();
  fixture.detectChanges();
  expect(fixture.nativeElement.textContent).toContain('Aucun site déclaré');
  fixture.componentInstance.targets.reload();
  TestBed.tick();
  http.expectOne('/api/targets').flush([
    { id: 'a', domain: 'verified.test', verified: true },
    { id: 'b', domain: 'waiting.test', verified: false },
  ]);
  await fixture.whenStable();
  fixture.detectChanges();
  expect(fixture.nativeElement.textContent).toContain('verified.test');
  expect(fixture.nativeElement.textContent).toContain('Vérifié');
  expect(fixture.nativeElement.textContent).toContain('À vérifier');
});

it('déclare le site et ouvre son détail', async () => {
  const fixture = TestBed.createComponent(TargetsPage);
  fixture.detectChanges();
  const http = TestBed.inject(HttpTestingController);
  http.expectOne('/api/targets').flush([]);
  await fixture.whenStable();
  const navigate = vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
  fixture.componentInstance.model.set({ url: 'demo.scanner.test' });
  fixture.nativeElement
    .querySelector('form')
    .dispatchEvent(new Event('submit', { cancelable: true }));
  const request = http.expectOne('/api/targets');
  expect(request.request.body).toEqual({ url: 'demo.scanner.test' });
  request.flush({ id: 'target' });
  await fixture.whenStable();
  expect(navigate).toHaveBeenCalledWith(['/targets', 'target']);
});

it('affiche une erreur de chargement et un bouton pour réessayer', async () => {
  const fixture = TestBed.createComponent(TargetsPage);
  fixture.detectChanges();
  TestBed.inject(HttpTestingController)
    .expectOne('/api/targets')
    .flush({}, { status: 503, statusText: 'Unavailable' });
  await fixture.whenStable();
  fixture.detectChanges();
  expect(fixture.nativeElement.textContent).toContain('temporairement indisponible');
  expect(fixture.nativeElement.textContent).toContain('Réessayer');
});
