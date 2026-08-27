import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test('guided agent workflow stages three proposals and preserves human approval', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveTitle(/PatchPilot/);
  await expect(page.getByRole('heading', { name: 'Prioritize what attackers can reach.' })).toBeVisible();

  await page.getByRole('button', { name: 'Run guided workflow' }).click();
  await expect(page.getByText('Complete', { exact: true }).first()).toBeVisible({ timeout: 12_000 });
  await expect(page.locator('.board-lane--proposed .remediation-card')).toHaveCount(3);
  await expect(page.locator('.run-receipt strong')).toHaveText(['12', '8', '3', '3']);

  await page.locator('.board-lane--proposed').getByRole('button', { name: 'Approve recommendation' }).first().click();
  const approvalDialog = page.getByRole('dialog', { name: /Approve CVE-/ });
  await expect(approvalDialog.getByText('This action is not exposed through WebMCP')).toBeVisible();
  await approvalDialog.getByRole('button', { name: 'Confirm approval' }).click();
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

test('human context changes agent scope, prompt, and remediation window', async ({ page }) => {
  await page.goto('/');
  await page.locator('.context-button').click();
  const dialog = page.getByRole('dialog', { name: 'Analysis context' });
  await dialog.locator('.choice-card').filter({ hasText: 'Balanced' }).click();
  await dialog.locator('.toggle-row').click();
  await dialog.getByLabel('Remediation window').selectOption('14');
  await dialog.getByRole('button', { name: 'Save context' }).click();

  await expect(page.locator('.prompt-box')).toContainText('high-risk vulnerabilities');
  await expect(page.locator('.prompt-box')).toContainText('synthetic asset inventory');
  await expect(page.locator('.prompt-box')).toContainText('14-day remediation plan');
  await expect(page.getByRole('heading', { name: '14-day remediation board' })).toBeVisible();

  await page.getByRole('button', { name: 'Run guided workflow' }).click();
  await expect(page.getByText('Complete', { exact: true }).first()).toBeVisible({ timeout: 12_000 });
  await expect(page.locator('.workflow-stage').last()).toContainText('Stage 14-day plan');
  await expect(page.getByRole('heading', { name: '14-day remediation board' })).toBeVisible();
});

test('document.modelContext tools execute the visible end-to-end workflow', async ({ page }) => {
  await page.addInitScript(() => {
    const registeredTools: unknown[] = [];
    Object.defineProperty(window, '__patchPilotRegisteredTools', { value: registeredTools });
    Object.defineProperty(Document.prototype, 'modelContext', {
      configurable: true,
      get() {
        return {
          registerTool: async (tool: unknown, options?: { signal?: AbortSignal }) => {
            const candidate = tool as { name: string };
            if (registeredTools.some((registered) => (registered as { name: string }).name === candidate.name)) {
              throw new Error(`Duplicate active tool: ${candidate.name}`);
            }
            registeredTools.push(tool);
            options?.signal?.addEventListener('abort', () => {
              const index = registeredTools.indexOf(tool);
              if (index >= 0) registeredTools.splice(index, 1);
            }, { once: true });
          },
        };
      },
    });
  });

  await page.goto('/');
  await expect.poll(() => page.evaluate(() => (
    window as Window & { __patchPilotRegisteredTools: unknown[] }
  ).__patchPilotRegisteredTools.length)).toBe(4);
  await expect(page.locator('.sidebar-footer')).toContainText('WebMCP ready');

  const result = await page.evaluate(async () => {
    type RuntimeTool = {
      name: string;
      execute: (input: Record<string, unknown>, options?: { signal: AbortSignal }) => Promise<Record<string, unknown>>;
    };
    const tools = (window as Window & { __patchPilotRegisteredTools: RuntimeTool[] }).__patchPilotRegisteredTools;
    const byName = new Map(tools.map((tool) => [tool.name, tool]));
    const signal = new AbortController().signal;
    const search = await byName.get('search_vulnerabilities')!.execute({ knownExploitedOnly: true, limit: 12 });
    const vulnerabilities = search.vulnerabilities as { cveId: string }[];
    const affected = await byName.get('find_affected_assets')!.execute({
      cveIds: vulnerabilities.map((item) => item.cveId),
      internetFacingOnly: true,
    }, { signal });
    const findings = affected.findings as { findingId: string }[];
    const prioritized = await byName.get('prioritize_findings')!.execute({
      findingIds: findings.map((item) => item.findingId),
      limit: 3,
    }, { signal });
    const ranked = prioritized.findings as { findingId: string }[];
    const plan = await byName.get('create_remediation_plan')!.execute({
      findingIds: ranked.map((item) => item.findingId),
      count: 3,
      windowDays: 7,
    }, { signal });
    return { names: tools.map((tool) => tool.name), search, affected, prioritized, plan };
  });

  expect(result.names).toEqual([
    'search_vulnerabilities',
    'find_affected_assets',
    'prioritize_findings',
    'create_remediation_plan',
  ]);
  expect(result.search.recommendedNextTool).toBe('find_affected_assets');
  expect(result.affected.recommendedNextTool).toBe('prioritize_findings');
  expect(result.prioritized.recommendedNextTool).toBe('create_remediation_plan');
  expect(result.plan).toMatchObject({ created: 3, approvalRequired: true, agentCanApprove: false, requiredNextActor: 'human' });
  await expect(page.locator('.workflow-stage--complete')).toHaveCount(4);
  await expect(page.locator('.board-lane--proposed .remediation-card')).toHaveCount(3);
  await expect(page.getByText('Human review gate')).toBeVisible();
});

test('same-origin KEV refresh visibly activates live data', async ({ page }) => {
  await page.route('**/api/cisa-kev', (route) => route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({
      title: 'CISA Known Exploited Vulnerabilities Catalog',
      catalogVersion: '2026.08.27-test',
      dateReleased: '2026-08-27T12:00:00.000Z',
      vulnerabilities: [{
        cveID: 'CVE-2024-3400',
        vendorProject: 'Palo Alto Networks',
        product: 'PAN-OS',
        vulnerabilityName: 'PAN-OS Command Injection Vulnerability',
        dateAdded: '2024-04-12',
        shortDescription: 'Public test fixture sourced from the CISA KEV schema.',
        requiredAction: 'Apply mitigations per vendor instructions.',
        dueDate: '2024-04-19',
        knownRansomwareCampaignUse: 'Unknown',
      }],
    }),
  }));
  await page.goto('/');
  await page.getByRole('button', { name: 'Refresh CISA KEV data' }).click();
  await expect(page.locator('.data-health span')).toHaveText('Live KEV');
  await expect(page.getByRole('status')).toContainText('Live CISA KEV loaded');
  await expect(page.getByText('CISA KEV catalog refreshed')).toBeAttached();
});

test('live-source failure visibly retains the bundled snapshot', async ({ page }) => {
  await page.route('**/api/cisa-kev', (route) => route.abort('failed'));
  await page.goto('/');
  await page.getByRole('button', { name: 'Refresh CISA KEV data' }).click();
  await expect(page.getByText('Live refresh unavailable', { exact: true })).toBeVisible();
  await expect(page.locator('.data-health span')).toHaveText('Snapshot');
  await expect(page.getByRole('status')).toContainText('bundled snapshot retained');
  await expect(page.getByRole('heading', { name: 'Actionable findings' })).toBeVisible();
});

test('mobile layout keeps navigation and primary workflow usable', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'mobile-chrome', 'Mobile-only assertion');
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Prioritize what attackers can reach.' })).toBeVisible();
  const agentTop = await page.locator('.agent-panel').evaluate((element) => element.getBoundingClientRect().top);
  const findingsTop = await page.locator('#findings').evaluate((element) => element.getBoundingClientRect().top);
  expect(agentTop).toBeLessThan(findingsTop);
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
