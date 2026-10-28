import { execFileSync, spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { expect, test } from '@playwright/test';

const root = resolve(__dirname, '../..');
// Mesuré sur la pile Docker : E, 31/100 (8 constats d'en-têtes + TLS 1.1). Surchargeable.
const expectedGrade = process.env['DEMO_EXPECTED_GRADE'] ?? 'E';

function publishTxt(value: string) {
  if (!/^scanner-verify=[A-Za-z0-9_-]+$/.test(value)) throw new Error('Jeton DNS inattendu');
  const compose = ['compose', 'exec', '-T', 'demo-dns'];
  const oldZone = execFileSync('docker', [...compose, 'cat', '/zones/scanner.test.zone'], {
    cwd: root,
    encoding: 'utf8',
    timeout: 15_000,
  });
  const previousSerial = /\(\s*(\d+)/.exec(oldZone)?.[1];
  if (!previousSerial) throw new Error('Numéro SOA absent de la zone');
  const serial = (Number(previousSerial) + 1) % 2 ** 32;
  const zone =
    '$ORIGIN scanner.test.\n$TTL 1\n' +
    `@ IN SOA ns.scanner.test. hostmaster.scanner.test. (${serial} 60 60 3600 1)\n` +
    '@ IN NS ns.scanner.test.\nns IN A 172.30.53.53\n' +
    `demo IN TXT "${value}"\n`;
  const write = spawnSync(
    'docker',
    [
      ...compose,
      '/bin/sh',
      '-ec',
      'cat > /zones/scanner.test.zone.tmp; mv /zones/scanner.test.zone.tmp /zones/scanner.test.zone',
    ],
    { cwd: root, input: zone, encoding: 'utf8', timeout: 15_000 },
  );
  if (write.error) throw write.error;
  if (write.status !== 0) throw new Error(`Publication DNS impossible : ${write.stderr}`);
}

test('inscription, connexion, preuve DNS et rapport TLS sans violation CSP', async ({ page }) => {
  const cspErrors: string[] = [];
  const pageErrors: string[] = [];
  await page.addInitScript(() => {
    document.addEventListener('securitypolicyviolation', (event) => {
      console.error(`CSP violation: ${event.violatedDirective} ${event.blockedURI}`);
    });
  });
  page.on('console', (message) => {
    if (
      message.type() === 'error' &&
      /content security policy|content-security-policy|CSP|violates.*directive/i.test(
        message.text(),
      )
    ) {
      cspErrors.push(message.text());
    }
  });
  page.on('pageerror', (error) => pageErrors.push(error.message));
  const credentials = {
    email: `browser-${randomUUID()}@scanner.test`,
    password: `Demo-${randomUUID()}`,
  };

  const response = await page.goto('/register');
  const policy = response?.headers()['content-security-policy'] ?? '';
  expect(policy).toContain("frame-ancestors 'none'");
  expect(policy).not.toContain('unsafe-inline');
  const nonce = /'nonce-([^']+)'/.exec(policy)?.[1];
  expect(nonce).toBeTruthy();
  expect(await page.locator('app-root').getAttribute('ngCspNonce')).toBe(nonce);
  await page.getByLabel('Adresse e-mail', { exact: true }).fill(credentials.email);
  await page.getByLabel('Mot de passe', { exact: true }).fill(credentials.password);
  await page.getByRole('button', { name: 'Créer mon compte', exact: true }).click();
  await expect(page.getByText('Compte créé. Connectez-vous pour continuer.')).toBeVisible();
  await page.getByLabel('Adresse e-mail', { exact: true }).fill(credentials.email);
  await page.getByLabel('Mot de passe', { exact: true }).fill(credentials.password);
  await page.getByRole('button', { name: 'Se connecter', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Mes sites', exact: true })).toBeVisible();
  await page.getByLabel('Domaine ou URL', { exact: true }).fill('demo.scanner.test');
  await page.getByRole('button', { name: 'Déclarer', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'demo.scanner.test', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Lancer un scan', exact: true })).toBeDisabled();
  publishTxt((await page.getByTestId('dns-value').textContent())!.trim());
  await expect(async () => {
    if (!(await page.getByText('Propriété vérifiée.', { exact: true }).isVisible())) {
      await page.getByRole('button', { name: 'Vérifier', exact: true }).click();
    }
    await expect(page.getByText('Propriété vérifiée.', { exact: true })).toBeVisible({
      timeout: 1000,
    });
  }).toPass({ timeout: 30_000, intervals: [1000, 2000] });
  await page.getByRole('button', { name: 'Lancer un scan', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Rapport de sécurité', exact: true })).toBeVisible(
    { timeout: 320_000 },
  );
  await expect(
    page.getByTestId('report-grade').getByLabel(`Note ${expectedGrade}`, { exact: true }),
  ).toBeVisible();
  await expect(
    page.locator('section[aria-labelledby="report-heading"] li').filter({
      has: page.getByText('TLS', { exact: true }),
    }),
  ).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Constats', exact: true })).toBeVisible();
  await expect(page.locator('article.finding').first()).toBeVisible();
  expect(
    await page.locator('style').evaluateAll((styles) => styles.map((style) => style.nonce)),
  ).toEqual(expect.arrayContaining([nonce]));
  expect(cspErrors).toEqual([]);
  expect(pageErrors).toEqual([]);
});
