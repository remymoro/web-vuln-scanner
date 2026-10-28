import { HttpClient, httpResource } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import {
  Credentials,
  RequestedScan,
  Scan,
  ScanReport,
  Target,
  TokenResponse,
  User,
} from './api.models';

@Injectable({ providedIn: 'root' })
export class ApiClient {
  private readonly http = inject(HttpClient);

  register(credentials: Credentials) {
    return this.http.post<User>('/api/auth/register', credentials);
  }

  login(credentials: Credentials) {
    return this.http.post<TokenResponse>('/api/auth/login', credentials);
  }

  me() {
    return this.http.get<User>('/api/auth/me');
  }

  targets() {
    return httpResource<Target[]>(() => '/api/targets', { defaultValue: [] });
  }

  target(id: () => string | undefined) {
    return httpResource<Target>(() => this.path('/targets', id()));
  }

  targetScans(id: () => string | undefined) {
    return httpResource<Scan[]>(() => this.path('/targets', id(), '/scans'), { defaultValue: [] });
  }

  declareTarget(url: string) {
    return this.http.post<Target>('/api/targets', { url });
  }

  verifyTarget(id: string) {
    return this.http.post<Target>(this.path('/targets', id, '/verify')!, {});
  }

  requestScan(targetId: string) {
    return this.http.post<RequestedScan>('/api/scans', { target_id: targetId });
  }

  scan(id: () => string | undefined) {
    return httpResource<Scan>(() => this.path('/scans', id()));
  }

  report(id: () => string | undefined) {
    return httpResource<ScanReport>(() => this.path('/scans', id(), '/report'));
  }

  private path(base: string, id: string | undefined, suffix = '') {
    return id ? `/api${base}/${encodeURIComponent(id)}${suffix}` : undefined;
  }
}
