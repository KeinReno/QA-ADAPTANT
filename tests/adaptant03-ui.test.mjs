import test from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { listenOrchestrator, loopbackBaseUrl } from '../apps/orchestrator/http.mjs';
import { approvedLocalTask } from './adaptant03-e2e-support.mjs';

test('local browser UI creates, approves, starts, and observes one trusted Task', { timeout: 150000 }, async t => {
  const { world, service } = await approvedLocalTask(t);
  const server = await listenOrchestrator({
    service,
    host: '127.0.0.1',
    port: 0,
    authenticate: async () => 'local-owner',
    issuePlanApproval: async ({ plan }) => `owner-plan:${plan.sha256}`,
    environmentRef: world.stand.environmentId
  });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const address = server.address();
  const browser = await chromium.launch({ headless: true });
  t.after(() => browser.close());
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${address.port}/`);
  await page.locator('#request').fill('Проверь локальный trusted сценарий создания записи с точными значениями.');
  await page.getByRole('button', { name: 'Создать Task и составить план' }).click();
  await page.getByRole('status').filter({ hasText: 'AWAITING_APPROVAL' }).waitFor({ timeout: 30000 });
  await page.getByRole('button', { name: 'Подтвердить план' }).click();
  await page.getByRole('status').filter({ hasText: 'READY' }).waitFor({ timeout: 15000 });
  await page.getByRole('button', { name: 'Запустить trusted шаг' }).click();
  await page.getByRole('status').filter({ hasText: 'COMPLETED' }).waitFor({ timeout: 30000 });
  assert.match(await page.locator('#task').textContent(), /COMPLETED/);
  assert.match(await page.locator('#events').textContent(), /PASS/);
  assert.match(await page.locator('#plan').textContent(), /MOCK/);
  assert.equal(world.stand.mutationCount, 1);
});

test('IPv6 loopback URL authority is bracketed and non-loopback hosts are rejected', () => {
  assert.equal(loopbackBaseUrl('::1'), 'http://[::1]');
  assert.equal(loopbackBaseUrl('127.0.0.1'), 'http://127.0.0.1');
  assert.throws(() => loopbackBaseUrl('0.0.0.0'), /loopback/);
});
