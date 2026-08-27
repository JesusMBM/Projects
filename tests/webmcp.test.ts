import { beforeEach, describe, expect, it } from 'vitest';
import { patchPilotStore } from '../src/store/patchPilotStore';
import { buildPatchPilotTools } from '../src/webmcp/registerTools';

function execute(toolName: string, input: Record<string, unknown>, aborted = false) {
  const tool = buildPatchPilotTools().find((candidate) => candidate.name === toolName)!;
  const controller = new AbortController();
  if (aborted) controller.abort();
  return tool.execute(input, { signal: controller.signal });
}

function executeWithoutOptions(toolName: string, input: Record<string, unknown>) {
  const tool = buildPatchPilotTools().find((candidate) => candidate.name === toolName)!;
  return tool.execute(input, undefined as unknown as WebMCP.ToolExecuteCallbackOptions);
}

describe('WebMCP tool contract', () => {
  beforeEach(() => {
    patchPilotStore.resetDemo();
  });

  it('exposes exactly four focused tools with accurate mutation hints', () => {
    const tools = buildPatchPilotTools();
    expect(tools.map((tool) => tool.name)).toEqual([
      'search_vulnerabilities',
      'find_affected_assets',
      'prioritize_findings',
      'create_remediation_plan',
    ]);
    expect(tools.slice(0, 3).every((tool) => tool.annotations?.readOnlyHint)).toBe(true);
    expect(tools[3].annotations?.readOnlyHint).toBe(false);
    expect(tools.every((tool) => tool.annotations?.untrustedContentHint)).toBe(true);
  });

  it('validates in application code and returns a corrective error', async () => {
    const result = await execute('create_remediation_plan', { count: 99 });
    expect(result).toEqual({ ok: false, error: 'count must be an integer from 1 to 3' });
    expect(patchPilotStore.getState().board).toHaveLength(0);
  });

  it('rejects unknown fields and explicit empty ID lists', async () => {
    await expect(execute('search_vulnerabilities', { surprise: true })).resolves.toEqual({
      ok: false,
      error: 'Unknown input field: surprise',
    });
    await expect(execute('create_remediation_plan', { findingIds: [] })).resolves.toEqual({
      ok: false,
      error: 'findingIds must be a non-empty array of no more than 3 valid IDs',
    });
    expect(patchPilotStore.getState().board).toHaveLength(0);
  });

  it('rejects invented finding IDs before changing the shared view', async () => {
    const originalFindings = patchPilotStore.getState().findings;
    const result = await execute('prioritize_findings', {
      findingIds: ['CVE-2099-9999:AST-999'],
      limit: 3,
    });

    expect(result).toEqual({
      ok: false,
      error: 'findingIds contains an ID that is not present in the current findings view',
    });
    expect(patchPilotStore.getState().findings).toEqual(originalFindings);
  });

  it('updates visible shared state before returning', async () => {
    const searchResult = await execute('search_vulnerabilities', {
      knownExploitedOnly: true,
      limit: 5,
    }) as { ok: boolean; vulnerabilities: { cveId: string }[] };
    expect(searchResult.ok).toBe(true);
    expect(patchPilotStore.getState().searchResults).toHaveLength(5);

    const assetResult = await execute('find_affected_assets', {
      cveIds: searchResult.vulnerabilities.map((item) => item.cveId),
      internetFacingOnly: true,
    }) as { ok: boolean; findings: { findingId: string }[] };
    expect(assetResult.ok).toBe(true);
    expect(patchPilotStore.getState().findings.length).toBeGreaterThan(0);

    const ranked = await execute('prioritize_findings', {
      findingIds: assetResult.findings.map((item) => item.findingId),
      limit: 3,
    }) as { findings: { findingId: string }[] };
    expect(patchPilotStore.getState().findings).toHaveLength(3);

    const plan = await execute('create_remediation_plan', {
      findingIds: ranked.findings.map((item) => item.findingId),
      count: 3,
      windowDays: 7,
    }) as { created: number; approvalRequired: boolean };
    expect(plan).toMatchObject({ created: 3, approvalRequired: true });
    expect(patchPilotStore.getState().board.every((item) => item.status === 'proposed')).toBe(true);
  });

  it('applies human context to an omitted-input tool chain', async () => {
    const originalContext = patchPilotStore.getState().context;
    patchPilotStore.updateContext({
      ...originalContext,
      riskPosture: 'balanced',
      internetFacingOnly: false,
      remediationWindowDays: 14,
    });

    const search = await execute('search_vulnerabilities', {}) as {
      contextApplied: { remediationWindowDays: number; riskPosture: string };
    };
    const affected = await execute('find_affected_assets', {}) as { totalMatches: number };
    await execute('prioritize_findings', { limit: 3 });
    const plan = await execute('create_remediation_plan', { count: 3 }) as { created: number };

    expect(search.contextApplied).toMatchObject({ remediationWindowDays: 14, riskPosture: 'balanced' });
    expect(affected.totalMatches).toBeGreaterThan(8);
    expect(plan.created).toBe(3);
    expect(patchPilotStore.getState().board.map((item) => item.targetDay)).toEqual([1, 8, 14]);
    expect(patchPilotStore.getState().workflowStages.at(-1)?.label).toBe('Stage 14-day plan');

    patchPilotStore.updateContext(originalContext);
  });

  it('returns a cancellation result without touching state', async () => {
    const result = await execute('search_vulnerabilities', {}, true);
    expect(result).toEqual({ ok: false, error: 'Tool execution was cancelled' });
  });

  it('supports browser invocations that omit callback options', async () => {
    const result = await executeWithoutOptions('search_vulnerabilities', {
      knownExploitedOnly: true,
      limit: 3,
    });
    expect(result).toMatchObject({
      ok: true,
      totalMatches: expect.any(Number),
      returned: 3,
      recommendedNextTool: 'find_affected_assets',
    });
  });
});
