import { HttpErrorResponse, HttpHeaders } from '@angular/common/http';
import { translateApiError } from './api-error';

const error = (status: number, detail?: unknown, retryAfter?: string) =>
  new HttpErrorResponse({
    status,
    error: { detail },
    headers: new HttpHeaders(retryAfter ? { 'Retry-After': retryAfter } : {}),
  });

it.each([
  ['Target not verified', 'Vérifiez la propriété'],
  ['Scan already active', 'déjà en cours'],
  ['Email already registered', 'déjà utilisée'],
  ['Domain already registered', 'déjà dans vos sites'],
])('traduit le conflit %s', (detail, message) => {
  expect(translateApiError(error(409, detail)).message).toContain(message);
});

it('affiche le nom et la valeur TXT attendus lors du refus de vérification', () => {
  const result = translateApiError(
    error(400, 'Expected TXT record at demo.test: scanner-verify=abc'),
  );
  expect(result.message).toContain('demo.test');
  expect(result.message).toContain('scanner-verify=abc');
});

it.each([
  [401, 'Reconnectez-vous'],
  [422, '12 à 128'],
  [503, 'temporairement indisponible'],
  [0, 'connexion'],
  [404, 'introuvable'],
  [500, 'serveur'],
])('traduit HTTP %i', (status, message) => {
  expect(translateApiError(error(status)).message).toContain(message);
});

it('traduit les identifiants incorrects sans confondre avec la session expirée', () => {
  expect(translateApiError(error(401, 'Invalid email or password')).message).toContain('incorrect');
});

it('convertit Retry-After en échéance, en secondes ou en date HTTP', () => {
  const now = Date.UTC(2026, 0, 1);
  expect(translateApiError(error(429, '', '30'), now).retryAt).toBe(now + 30000);
  expect(translateApiError(error(429, '', new Date(now + 60000).toUTCString()), now).retryAt).toBe(
    now + 60000,
  );
  expect(translateApiError(error(429, '', 'invalide'), now).retryAt).toBeUndefined();
  expect(translateApiError(error(429), now).retryAt).toBeUndefined();
  expect(translateApiError(error(429, '', '0'), now).retryAt).toBe(now);
});
