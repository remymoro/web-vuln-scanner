import {
  HttpClient,
  HttpErrorResponse,
  provideHttpClient,
  withInterceptors,
} from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import {
  ActivatedRouteSnapshot,
  provideRouter,
  Router,
  RouterStateSnapshot,
  UrlTree,
} from '@angular/router';
import { AuthService, TOKEN_KEY } from './auth-service';
import { authGuard } from './auth-guard';
import { authInterceptor } from './auth-interceptor';

const credentials = { email: 'remy@example.test', password: 'a-long-password' };

function setup() {
  TestBed.configureTestingModule({
    providers: [
      provideHttpClient(withInterceptors([authInterceptor])),
      provideHttpClientTesting(),
      provideRouter([]),
    ],
  });
  return {
    auth: TestBed.inject(AuthService),
    http: TestBed.inject(HttpTestingController),
    client: TestBed.inject(HttpClient),
    router: TestBed.inject(Router),
  };
}

beforeEach(() => sessionStorage.clear());
afterEach(() => {
  TestBed.inject(HttpTestingController).verify();
  sessionStorage.clear();
});

it('restaure le jeton de session et expose un état réactif', () => {
  sessionStorage.setItem(TOKEN_KEY, 'saved-token');
  const { auth } = setup();
  expect(auth.token()).toBe('saved-token');
  expect(auth.authenticated()).toBe(true);
  auth.logout();
  expect(auth.token()).toBeNull();
  expect(auth.authenticated()).toBe(false);
  expect(sessionStorage.getItem(TOKEN_KEY)).toBeNull();
});

it('stocke le jeton après connexion et actualise les signaux', async () => {
  const { auth, http } = setup();
  const result = auth.login(credentials);
  const request = http.expectOne('/api/auth/login');
  expect(request.request.body).toEqual(credentials);
  request.flush({ access_token: 'new-token', token_type: 'bearer' });
  await result;
  expect(sessionStorage.getItem(TOKEN_KEY)).toBe('new-token');
  expect(auth.token()).toBe('new-token');
  expect(auth.authenticated()).toBe(true);
});

it('ne conserve aucun jeton si la connexion échoue', async () => {
  const { auth, http, router } = setup();
  vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true);
  const result = auth.login(credentials);
  const assertion = expect(result).rejects.toBeInstanceOf(HttpErrorResponse);
  http
    .expectOne('/api/auth/login')
    .flush({ detail: 'Invalid email or password' }, { status: 401, statusText: 'Unauthorized' });
  await assertion;
  expect(auth.authenticated()).toBe(false);
  expect(sessionStorage.getItem(TOKEN_KEY)).toBeNull();
});

it('ajoute Bearer aux seuls appels de notre API', () => {
  sessionStorage.setItem(TOKEN_KEY, 'secret');
  const { client, http } = setup();
  client.get('/api/targets').subscribe();
  const api = http.expectOne('/api/targets');
  expect(api.request.headers.get('Authorization')).toBe('Bearer secret');
  api.flush([]);
  client.get('https://example.test/data').subscribe();
  const external = http.expectOne('https://example.test/data');
  expect(external.request.headers.has('Authorization')).toBe(false);
  external.flush({});
});

it('ne met pas d’en-tête sans jeton et propage les erreurs', () => {
  const { client, http } = setup();
  const error = vi.fn();
  client.get('/api/targets').subscribe({ error });
  const request = http.expectOne('/api/targets');
  expect(request.request.headers.has('Authorization')).toBe(false);
  request.flush({}, { status: 503, statusText: 'Unavailable' });
  expect(error).toHaveBeenCalledWith(expect.objectContaining({ status: 503 }));
});

it('déconnecte et redirige vers /login sur 401', () => {
  sessionStorage.setItem(TOKEN_KEY, 'expired');
  const { auth, router, client, http } = setup();
  const navigate = vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true);
  client.get('/api/targets').subscribe({ error: () => undefined });
  http.expectOne('/api/targets').flush({}, { status: 401, statusText: 'Unauthorized' });
  expect(auth.authenticated()).toBe(false);
  expect(sessionStorage.getItem(TOKEN_KEY)).toBeNull();
  expect(navigate).toHaveBeenCalledWith('/login');
});

it('la garde exige une session et produit une redirection /login', () => {
  const { auth } = setup();
  const guard = () =>
    TestBed.runInInjectionContext(() =>
      authGuard({} as ActivatedRouteSnapshot, {} as RouterStateSnapshot),
    );
  const redirect = guard() as UrlTree;
  expect(redirect.toString()).toBe('/login');
  sessionStorage.setItem(TOKEN_KEY, 'token');
  // Une modification du stockage seule ne crée pas de session dans le service.
  expect(auth.authenticated()).toBe(false);
});

it('la garde accepte une session restaurée', () => {
  sessionStorage.setItem(TOKEN_KEY, 'token');
  setup();
  expect(
    TestBed.runInInjectionContext(() =>
      authGuard({} as ActivatedRouteSnapshot, {} as RouterStateSnapshot),
    ),
  ).toBe(true);
});
