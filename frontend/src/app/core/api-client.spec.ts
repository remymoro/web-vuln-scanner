import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { ApiClient } from './api-client';

let api: ApiClient;
let http: HttpTestingController;
beforeEach(() => {
  TestBed.configureTestingModule({ providers: [provideHttpClient(), provideHttpClientTesting()] });
  api = TestBed.inject(ApiClient);
  http = TestBed.inject(HttpTestingController);
});
afterEach(() => http.verify());

it('respecte les routes, méthodes et corps des mutations', () => {
  const credentials = { email: 'a@example.test', password: 'long-password' };
  api.register(credentials).subscribe();
  api.login(credentials).subscribe();
  api.me().subscribe();
  api.declareTarget('example.test').subscribe();
  api.verifyTarget('target').subscribe();
  api.requestScan('target').subscribe();
  for (const [url, method, body] of [
    ['/api/auth/register', 'POST', credentials],
    ['/api/auth/login', 'POST', credentials],
    ['/api/auth/me', 'GET', null],
    ['/api/targets', 'POST', { url: 'example.test' }],
    ['/api/targets/target/verify', 'POST', {}],
    ['/api/scans', 'POST', { target_id: 'target' }],
  ] as const) {
    const request = http.expectOne(url);
    expect(request.request.method).toBe(method);
    expect(request.request.body).toEqual(body);
    request.flush({});
  }
});

it('charge les ressources typées, dont le nouvel historique', async () => {
  const resources = TestBed.runInInjectionContext(() => [
    api.targets(),
    api.target(() => 'target'),
    api.targetScans(() => 'target'),
    api.scan(() => 'scan'),
    api.report(() => 'scan'),
  ]);
  TestBed.tick();
  for (const [index, url, body] of [
    [0, '/api/targets', []],
    [1, '/api/targets/target', { id: 'target' }],
    [2, '/api/targets/target/scans', []],
    [3, '/api/scans/scan', { id: 'scan' }],
    [4, '/api/scans/scan/report', { score: 42 }],
  ] as const) {
    const request = http.expectOne(url);
    expect(request.request.method).toBe('GET');
    request.flush(body);
    await Promise.resolve();
    expect(resources[index].value()).toEqual(body);
  }
});

it('ne charge pas une ressource sans identifiant', () => {
  TestBed.runInInjectionContext(() => api.report(() => undefined));
  TestBed.tick();
  http.expectNone(() => true);
});
