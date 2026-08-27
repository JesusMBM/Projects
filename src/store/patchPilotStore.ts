import { useSyncExternalStore } from 'react';
import { inventory } from '../data/inventory';
import { vulnerabilitySnapshot } from '../data/vulnerabilities';
import {
  createRemediationPlan,
  findAffectedAssets,
  prioritizeFindings,
  searchVulnerabilities,
} from '../domain/engine';
import type {
  ActivityEvent,
  AffectedAssetsInput,
  OrganizationContext,
  PatchPilotState,
  PlanInput,
  PrioritizeInput,
  RemediationItem,
  SearchInput,
  WorkflowStage,
} from '../domain/types';
import { refreshKevCatalog } from '../services/kevSource';

type Listener = () => void;

const initialStages: WorkflowStage[] = [
  { id: 'search', label: 'Search exploited CVEs', tool: 'search_vulnerabilities', status: 'pending', detail: 'Waiting' },
  { id: 'match', label: 'Match synthetic assets', tool: 'find_affected_assets', status: 'pending', detail: 'Waiting' },
  { id: 'prioritize', label: 'Rank business risk', tool: 'prioritize_findings', status: 'pending', detail: 'Waiting' },
  { id: 'plan', label: 'Stage seven-day plan', tool: 'create_remediation_plan', status: 'pending', detail: 'Waiting' },
];

function stagesForWindow(windowDays: number) {
  return initialStages.map((stage) => (
    stage.id === 'plan' ? { ...stage, label: `Stage ${windowDays}-day plan` } : { ...stage }
  ));
}

const defaultContext: OrganizationContext = {
  organizationName: 'Northstar Commerce',
  focus: 'Protect customer-facing commerce and workforce access',
  riskPosture: 'aggressive',
  internetFacingOnly: true,
  remediationWindowDays: 7,
};

const emptyWorkflowSummary = {
  searched: 0,
  matched: 0,
  prioritized: 0,
  proposals: 0,
};

const initialFindings = prioritizeFindings(
  findAffectedAssets(vulnerabilitySnapshot, inventory),
  { limit: 50 },
);

let state: PatchPilotState = {
  context: defaultContext,
  vulnerabilities: vulnerabilitySnapshot,
  searchResults: vulnerabilitySnapshot,
  findings: initialFindings,
  board: [],
  activity: [
    {
      id: 'EVT-BOOT',
      time: 'Ready',
      label: 'Clean-room dataset loaded',
      detail: '15 synthetic assets · bundled public CVE/KEV snapshot',
      kind: 'data',
    },
  ],
  dataSource: {
    mode: 'bundled',
    label: 'Bundled public snapshot',
    snapshotDate: '2026-08-27',
    catalogVersion: 'curated-demo-v1',
    lastChecked: null,
    fallbackReason: null,
  },
  webMcpStatus: 'checking',
  workflowStatus: 'idle',
  workflowStages: initialStages,
  workflowSummary: emptyWorkflowSummary,
};

const listeners = new Set<Listener>();

function emit() {
  listeners.forEach((listener) => listener());
}

function setState(next: PatchPilotState | ((current: PatchPilotState) => PatchPilotState)) {
  state = typeof next === 'function' ? next(state) : next;
  emit();
}

function activity(label: string, detail: string, kind: ActivityEvent['kind']): ActivityEvent {
  return {
    id: `EVT-${Date.now()}-${Math.random().toString(16).slice(2, 6)}`,
    time: new Intl.DateTimeFormat('en-US', { hour: 'numeric', minute: '2-digit' }).format(new Date()),
    label,
    detail,
    kind,
  };
}

function pushActivity(event: ActivityEvent) {
  setState((current) => ({ ...current, activity: [event, ...current.activity].slice(0, 12) }));
}

function updateStage(id: WorkflowStage['id'], status: WorkflowStage['status'], detail: string) {
  setState((current) => ({
    ...current,
    workflowStages: current.workflowStages.map((stage) => (stage.id === id ? { ...stage, status, detail } : stage)),
  }));
}

function updateFindingsForCurrentCatalog(catalog = state.vulnerabilities) {
  return prioritizeFindings(findAffectedAssets(catalog, inventory), { limit: 50 });
}

export const patchPilotStore = {
  getState: () => state,
  subscribe(listener: Listener) {
    listeners.add(listener);
    return () => listeners.delete(listener);
  },
  setWebMcpStatus(status: PatchPilotState['webMcpStatus']) {
    setState((current) => ({ ...current, webMcpStatus: status }));
  },
  updateContext(context: OrganizationContext) {
    setState((current) => ({
      ...current,
      context,
      workflowStatus: 'idle',
      workflowStages: stagesForWindow(context.remediationWindowDays),
      workflowSummary: { ...emptyWorkflowSummary },
    }));
    pushActivity(activity('Analysis context updated', `${context.organizationName} · ${context.remediationWindowDays}-day window`, 'human'));
  },
  search(input: SearchInput = {}) {
    const effectiveInput: SearchInput = {
      ...input,
      knownExploitedOnly: input.knownExploitedOnly ?? (state.context.riskPosture === 'aggressive'),
      minCvss: input.minCvss ?? (state.context.riskPosture === 'balanced' ? 7 : undefined),
    };
    const result = searchVulnerabilities(state.vulnerabilities, effectiveInput);
    setState((current) => ({
      ...current,
      searchResults: result.vulnerabilities,
      workflowSummary: { ...current.workflowSummary, searched: result.total },
    }));
    pushActivity(activity('search_vulnerabilities completed', `${result.total} catalog matches focused in the shared view`, 'tool'));
    return result;
  },
  findAffected(input: AffectedAssetsInput = {}) {
    const catalog = input.cveIds?.length ? state.vulnerabilities : state.searchResults;
    const findings = findAffectedAssets(catalog, inventory, {
      ...input,
      internetFacingOnly: input.internetFacingOnly ?? state.context.internetFacingOnly,
    });
    setState((current) => ({
      ...current,
      findings,
      workflowSummary: { ...current.workflowSummary, matched: findings.length },
    }));
    pushActivity(activity('find_affected_assets completed', `${findings.length} synthetic asset matches focused in the shared view`, 'tool'));
    return findings;
  },
  prioritize(input: PrioritizeInput & { findingIds?: string[] } = {}) {
    const source = input.findingIds?.length
      ? state.findings.filter((finding) => input.findingIds?.includes(finding.id))
      : state.findings;
    const findings = prioritizeFindings(source, input);
    setState((current) => ({
      ...current,
      findings,
      workflowSummary: { ...current.workflowSummary, prioritized: findings.length },
    }));
    pushActivity(activity('prioritize_findings completed', `Top ${findings.length} ranked with explainable scoring`, 'tool'));
    return findings;
  },
  createPlan(input: PlanInput = {}) {
    const prioritized = prioritizeFindings(
      state.findings,
      { internetFacingOnly: state.context.internetFacingOnly, limit: 50 },
    );
    const created = createRemediationPlan(
      prioritized,
      state.board,
      {
        ...input,
        windowDays: input.windowDays ?? state.context.remediationWindowDays,
        objective: input.objective?.trim() || state.context.focus,
      },
    );
    setState((current) => ({
      ...current,
      board: [...created, ...current.board],
      workflowSummary: { ...current.workflowSummary, proposals: created.length },
    }));
    pushActivity(activity('create_remediation_plan completed', `${created.length} proposal${created.length === 1 ? '' : 's'} stopped at the human gate`, 'tool'));
    return created;
  },
  approveItem(id: string) {
    let approved: RemediationItem | undefined;
    setState((current) => ({
      ...current,
      board: current.board.map((item) => {
        if (item.id !== id) return item;
        approved = { ...item, status: 'approved', approvedAt: new Date().toISOString() };
        return approved;
      }),
    }));
    if (approved) pushActivity(activity('Recommendation approved', `${approved.cveId} on ${approved.hostname}`, 'human'));
  },
  updateItem(id: string, updates: Pick<RemediationItem, 'owner' | 'dueDate' | 'action' | 'notes'>) {
    let updated: RemediationItem | undefined;
    setState((current) => ({
      ...current,
      board: current.board.map((item) => {
        if (item.id !== id) return item;
        updated = { ...item, ...updates };
        return updated;
      }),
    }));
    if (updated) pushActivity(activity('Recommendation modified', `${updated.cveId} · owner ${updated.owner}`, 'human'));
  },
  resetDemo() {
    setState((current) => ({
      ...current,
      searchResults: current.vulnerabilities,
      findings: updateFindingsForCurrentCatalog(current.vulnerabilities),
      board: [],
      workflowStatus: 'idle',
      workflowStages: stagesForWindow(current.context.remediationWindowDays),
      workflowSummary: { ...emptyWorkflowSummary },
    }));
    pushActivity(activity('Demo workspace reset', 'Board cleared; source data retained', 'human'));
  },
  startWorkflow() {
    setState((current) => ({
      ...current,
      workflowStatus: 'running',
      workflowStages: stagesForWindow(current.context.remediationWindowDays),
      workflowSummary: { ...emptyWorkflowSummary },
    }));
  },
  beginToolExecution(id: WorkflowStage['id']) {
    setState((current) => {
      const stages = id === 'search' && current.workflowStatus !== 'running'
        ? stagesForWindow(current.context.remediationWindowDays)
        : current.workflowStages;
      return {
        ...current,
        workflowStatus: 'running',
        workflowSummary: id === 'search' && current.workflowStatus !== 'running'
          ? { ...emptyWorkflowSummary }
          : current.workflowSummary,
        workflowStages: stages.map((stage) => (
          stage.id === id ? { ...stage, status: 'running', detail: 'Invoked through document.modelContext' } : stage
        )),
      };
    });
  },
  completeToolExecution(id: WorkflowStage['id'], detail: string) {
    setState((current) => ({
      ...current,
      workflowStatus: id === 'plan' ? 'complete' : 'running',
      workflowStages: current.workflowStages.map((stage) => (
        stage.id === id ? { ...stage, status: 'complete', detail } : stage
      )),
    }));
  },
  failToolExecution(id: WorkflowStage['id'], detail: string) {
    setState((current) => ({
      ...current,
      workflowStatus: 'error',
      workflowStages: current.workflowStages.map((stage) => (
        stage.id === id ? { ...stage, status: 'error', detail } : stage
      )),
    }));
  },
  updateStage,
  completeWorkflow() {
    setState((current) => ({ ...current, workflowStatus: 'complete' }));
  },
  async refreshData(signal?: AbortSignal) {
    try {
      const result = await refreshKevCatalog(vulnerabilitySnapshot, signal);
      const findings = prioritizeFindings(findAffectedAssets(result.vulnerabilities, inventory), { limit: 50 });
      setState((current) => ({
        ...current,
        vulnerabilities: result.vulnerabilities,
        searchResults: result.vulnerabilities,
        findings,
        dataSource: {
          mode: 'live',
          label: 'Live CISA KEV catalog',
          snapshotDate: result.dateReleased.slice(0, 10),
          catalogVersion: result.catalogVersion,
          lastChecked: new Date().toISOString(),
          fallbackReason: null,
        },
      }));
      pushActivity(activity('CISA KEV catalog refreshed', `${result.catalogVersion} · ${result.vulnerabilities.length} records available`, 'data'));
      return { ok: true as const, count: result.vulnerabilities.length };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown network error';
      setState((current) => ({
        ...current,
        dataSource: {
          ...current.dataSource,
          mode: 'bundled',
          label: 'Bundled public snapshot',
          lastChecked: new Date().toISOString(),
          fallbackReason: message,
        },
      }));
      pushActivity(activity('Live refresh unavailable', 'Continuing with the bundled public snapshot', 'data'));
      return { ok: false as const, error: message };
    }
  },
};

export function usePatchPilotState() {
  return useSyncExternalStore(patchPilotStore.subscribe, patchPilotStore.getState, patchPilotStore.getState);
}

export { initialStages };
