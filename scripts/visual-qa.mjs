import { chromium } from 'playwright';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';

const baseUrl = process.env.PATCHPILOT_URL || 'http://127.0.0.1:4173';
const outputDirectory = path.resolve('.qa');
await mkdir(outputDirectory, { recursive: true });

const browser = await chromium.launch({ channel: 'chrome', headless: true });
const pageErrors = [];
const consoleErrors = [];

for (const viewport of [
  { name: 'mobile-375', width: 375, height: 812 },
  { name: 'tablet-768', width: 768, height: 1024 },
  { name: 'desktop-1440', width: 1440, height: 1000 },
]) {
  const page = await browser.newPage({ viewport: { width: viewport.width, height: viewport.height } });
  page.on('pageerror', (error) => pageErrors.push(`${viewport.name}: ${error.message}`));
  page.on('console', (message) => {
    if (message.type() === 'error') consoleErrors.push(`${viewport.name}: ${message.text()}`);
  });
  await page.goto(baseUrl, { waitUntil: 'networkidle' });
  await page.screenshot({ path: path.join(outputDirectory, `${viewport.name}-overview.png`), fullPage: true });

  await page.getByRole('button', { name: 'Run guided workflow' }).click();
  await page.getByText('Complete', { exact: true }).first().waitFor({ timeout: 15_000 });
  await page.locator('#remediation').scrollIntoViewIfNeeded();
  await page.locator('#remediation').screenshot({ path: path.join(outputDirectory, `${viewport.name}-remediation.png`) });
  const layout = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  if (layout.scrollWidth > layout.viewport) {
    pageErrors.push(`${viewport.name}: page overflow ${layout.scrollWidth}px > ${layout.viewport}px`);
  }
  await page.close();
}

await browser.close();

if (pageErrors.length || consoleErrors.length) {
  console.error(JSON.stringify({ pageErrors, consoleErrors }, null, 2));
  process.exitCode = 1;
} else {
  console.log('Visual QA captured 6 screenshots with 0 page errors and 0 console errors.');
}
