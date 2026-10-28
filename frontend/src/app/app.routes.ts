import { Routes } from '@angular/router';
import { authGuard } from './core/auth-guard';

export const routes: Routes = [
  {
    path: 'login',
    loadComponent: () => import('./features/auth/auth-page').then((m) => m.AuthPage),
  },
  {
    path: 'register',
    data: { mode: 'register' },
    loadComponent: () => import('./features/auth/auth-page').then((m) => m.AuthPage),
  },
  {
    path: 'targets',
    canActivate: [authGuard],
    children: [
      {
        path: '',
        pathMatch: 'full',
        loadComponent: () => import('./features/targets/targets-page').then((m) => m.TargetsPage),
      },
      {
        path: ':id',
        loadComponent: () => import('./features/targets/target-page').then((m) => m.TargetPage),
      },
    ],
  },
  {
    path: 'scans/:id',
    canActivate: [authGuard],
    loadComponent: () => import('./features/scans/scan-page').then((m) => m.ScanPage),
  },
  { path: '', pathMatch: 'full', redirectTo: 'targets' },
  { path: '**', redirectTo: 'targets' },
];
