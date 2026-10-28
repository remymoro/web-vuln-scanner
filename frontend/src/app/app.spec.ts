import { provideHttpClient } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { App } from './app';

it('affiche la navigation et un accès direct au contenu', () => {
  sessionStorage.clear();
  TestBed.configureTestingModule({ providers: [provideHttpClient(), provideRouter([])] });
  const fixture = TestBed.createComponent(App);
  fixture.detectChanges();
  expect(fixture.nativeElement.querySelector('nav').textContent).toContain('Connexion');
  expect(fixture.nativeElement.querySelector('.skip-link').getAttribute('href')).toBe('#main');
});
