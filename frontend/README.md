# Interface Angular

Depuis ce dossier : `source ~/.nvm/nvm.sh && nvm use`, puis `npm ci`.

- `npx ng serve` : développement sur http://127.0.0.1:4200 avec proxy `/api/` vers le port 8000.
- `npx ng test --watch=false` : tests Vitest.
- `npx ng build` : build de production dans `dist/frontend/browser`.
- `npm run e2e` : parcours Playwright contre la pile Compose complète, nginx compris.

Voir le [README du projet](../README.md#frontend-angular) pour préparer la pile,
libérer le port 4200 et publier la preuve DNS de démonstration.
