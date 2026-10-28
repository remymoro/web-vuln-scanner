import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, convertToParamMap, provideRouter, Router } from '@angular/router';
import { AuthPage } from './auth-page';

function setup(registering = false, registered = false) {
  TestBed.configureTestingModule({
    providers: [
      provideHttpClient(),
      provideHttpClientTesting(),
      provideRouter([]),
      {
        provide: ActivatedRoute,
        useValue: {
          snapshot: {
            data: { mode: registering ? 'register' : 'login' },
            queryParamMap: convertToParamMap(registered ? { registered: '1' } : {}),
          },
        },
      },
    ],
  });
  const fixture = TestBed.createComponent(AuthPage);
  fixture.detectChanges();
  return { fixture, page: fixture.componentInstance, http: TestBed.inject(HttpTestingController) };
}

afterEach(() => {
  TestBed.inject(HttpTestingController).verify();
  sessionStorage.clear();
});

it('affiche la connexion et la confirmation d’inscription', () => {
  const { fixture } = setup(false, true);
  expect(fixture.nativeElement.querySelector('h1').textContent).toBe('Connexion');
  expect(fixture.nativeElement.textContent).toContain('Compte créé');
});

it('valide l’e-mail et les limites du mot de passe avec Signal Forms', () => {
  const { page } = setup();
  page.model.set({ email: 'wrong', password: 'short' });
  expect(page.credentials.email().invalid()).toBe(true);
  expect(page.credentials.password().invalid()).toBe(true);
  page.model.set({ email: 'remy@example.test', password: 'x'.repeat(129) });
  expect(page.credentials.password().invalid()).toBe(true);
  for (const length of [12, 128]) {
    page.model.set({ email: 'remy@example.test', password: 'x'.repeat(length) });
    expect(page.credentials().valid()).toBe(true);
  }
});

it('inscrit puis renvoie vers la connexion', async () => {
  const { fixture, page, http } = setup(true);
  const navigate = vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
  expect(fixture.nativeElement.querySelector('h1').textContent).toBe('Créer un compte');
  page.model.set({ email: 'remy@example.test', password: 'x'.repeat(12) });
  fixture.nativeElement
    .querySelector('form')
    .dispatchEvent(new Event('submit', { cancelable: true }));
  http.expectOne('/api/auth/register').flush({ id: 'user', email: 'remy@example.test' });
  await fixture.whenStable();
  expect(navigate).toHaveBeenCalledWith(['/login'], { queryParams: { registered: '1' } });
});

it('affiche une erreur d’identifiants en français', async () => {
  const { fixture, page, http } = setup();
  page.model.set({ email: 'remy@example.test', password: 'x'.repeat(12) });
  fixture.nativeElement
    .querySelector('form')
    .dispatchEvent(new Event('submit', { cancelable: true }));
  http
    .expectOne('/api/auth/login')
    .flush({ detail: 'Invalid email or password' }, { status: 401, statusText: 'Unauthorized' });
  await fixture.whenStable();
  fixture.detectChanges();
  expect(fixture.nativeElement.textContent).toContain('mot de passe incorrect');
});
