import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test('guided agent workflow stages three proposals and preserves human approval', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveTitle(/PatchPilot/);
  await expect(page.getByRole('heading', { name: 'Prioritize what attackers can reach.' })).toBeVisible();

  await page.getByRole('button', { name: 'Run guided workflow' }).click();
  await expect(page.getByText('Complete', { exact: true }).first()).toBeVisible({ timeout: 12_000 });
  await expect(page.locator('.board-lane--proposed .remediation-card')).toHaveCount(3);

  await page.locator('.board-lane--proposed').getByRole('button', { name: 'Approve recommendation' }).first().click();
  await expect(page.locator('.board-lane--approved .remediation-card')).toHaveCount(1);
  await expect(page.locator('.board-lane--proposed .remediation-card')).toHaveCount(2);
  await expect(page.getByText('Approved by human')).toBeVisible();
});

test('tool registry exposes four tools and no agent approval action', async ({ page }) => {
  await page.goto('/');
  if ((page.viewportSize()?.width ?? 1280) <= 980) {
    await page.getByRole('button', { name: 'Open navigation' }).click();
  }
  await page.getByRole('button', { name: /Tool registry/ }).first().click();
  const drawer = page.getByRole('dialog', { name: 'WebMCP tool registry' });
  await expect(drawer).toBeVisible();
  await expect(drawer.locator('.tool-card')).toHaveCount(4);
  await expect(drawer.getByText('create_remediation_plan')).toBeVisible();
  await expect(drawer.getByText('update_remediation_status')).toHaveCount(0);
  await expect(drawer.getByText('Approval is intentionally absent')).toBeVisible();
});

test('live-source failure visibly retains the bundled snapshot', async ({ page }) => {
  await page.route('**/known_exploited_vulnerabilities.json', (route) => route.abort('failed'));
  await page.goto('/');
  await page.getByRole('button', { name: 'Refresh CISA KEV data' }).click();
  await expect(page.getByText('Live refresh unavailable')).toBeVisible();
  await expect(page.locator('.data-health span')).toHaveText('Snapshot');
  await expect(page.getByRole('heading', { name: 'Actionable findings' })).toBeVisible();
});

test('mobile layout keeps navigation and primary workflow usable', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'mobile-chrome', 'Mobile-only assertion');
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Prioritize what attackers can reach.' })).toBeVisible();
  await page.getByRole('button', { name: 'Open navigation' }).click();
  await expect(page.getByRole('navigation', { name: 'Primary navigation' })).toBeVisible();
  await page.getByRole('link', { name: /Findings/ }).click();
  await expect(page.locator('#findings')).toBeInViewport();
  await expect(page.locator('body')).not.toHaveCSS('overflow-x', 'scroll');
});

test('dashboard has no serious or critical automated accessibility violations', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop-chrome', 'Desktop accessibility audit');
  await page.goto('/');
  const results = await new AxeBuilder({ page }).analyze();
  const blocking = results.violations.filter((violation) => ['serious', 'critical'].includes(violation.impact ?? ''));
  const summary = blocking.map((violation) => ({
    id: violation.id,
    help: violation.help,
    nodes: violation.nodes.map((node) => ({
      target: node.target,
      message: node.any[0]?.message ?? node.failureSummary,
    })),
  }));
  expect(blocking.length, JSON.stringify(summary, null, 2)).toBe(0);
});
