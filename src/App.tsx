import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Bot,
  Check,
  CheckCircle2,
  ChevronDown,
  CircleAlert,
  ClipboardCheck,
  Clock3,
  Database,
  ExternalLink,
  FileSearch2,
  Gauge,
  Info,
  LayoutDashboard,
  ListFilter,
  LockKeyhole,
  Menu,
  Network,
  PackageCheck,
  Pencil,
  Play,
  Radar,
  RefreshCw,
  RotateCcw,
  Search,
  Server,
  Settings2,
  ShieldCheck,
  Sparkles,
  Target,
  UserCheck,
  X,
  Zap,
} from 'lucide-react';
import { inventory } from './data/inventory';
import { publicDataSources } from './data/vulnerabilities';
import type {
  Finding,
  OrganizationContext,
  RemediationItem,
  RemediationStatus,
  Severity,
} from './domain/types';
import { patchPilotStore, usePatchPilotState } from './store/patchPilotStore';
import { buildPatchPilotTools, registerPatchPilotTools } from './webmcp/registerTools';

function buildDemoPrompt(context: OrganizationContext) {
  const vulnerabilityScope = context.riskPosture === 'aggressive'
    ? 'actively exploited vulnerabilities'
    : 'high-risk vulnerabilities';
  const assetScope = context.internetFacingOnly ? 'our internet-facing systems' : 'our synthetic asset inventory';
  return `Find ${vulnerabilityScope} affecting ${assetScope}, prioritize the top three, and create a ${context.remediationWindowDays}-day remediation plan.`;
}

const wait = (milliseconds: number) => new Promise((resolve) => window.setTimeout(resolve, milliseconds));

function scoreTone(score: number) {
  if (score >= 90) return 'critical';
  if (score >= 75) return 'high';
  return 'guarded';
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric' }).format(
    new Date(`${value}T12:00:00`),
  );
}

function plural(count: number, single: string, multiple = `${single}s`) {
  return `${count} ${count === 1 ? single : multiple}`;
}

function App() {
  const state = usePatchPilotState();
  const demoPrompt = buildDemoPrompt(state.context);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [activePanel, setActivePanel] = useState<'context' | 'inventory' | 'tools' | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [editingItem, setEditingItem] = useState<RemediationItem | null>(null);
  const [approvingItem, setApprovingItem] = useState<RemediationItem | null>(null);
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState<Severity | 'all'>('all');
  const [kevOnly, setKevOnly] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [refreshNotice, setRefreshNotice] = useState<{ tone: 'success' | 'error'; text: string } | null>(null);
  const [copied, setCopied] = useState(false);
  const boardRef = useRef<HTMLElement>(null);

  useEffect(() => {
    return registerPatchPilotTools();
  }, []);

  const searchCveIds = useMemo(
    () => new Set(state.searchResults.map((vulnerability) => vulnerability.cveId)),
    [state.searchResults],
  );

  const visibleFindings = useMemo(() => {
    const normalized = query.trim().toLocaleLowerCase();
    return state.findings.filter((finding) => {
      if (!searchCveIds.has(finding.vulnerability.cveId)) return false;
      if (severity !== 'all' && finding.vulnerability.severity !== severity) return false;
      if (kevOnly && !finding.vulnerability.knownExploited) return false;
      if (!normalized) return true;
      return [
        finding.vulnerability.cveId,
        finding.vulnerability.vendor,
        finding.vulnerability.product,
        finding.asset.hostname,
        finding.asset.service,
        finding.asset.owner,
      ].some((value) => value.toLocaleLowerCase().includes(normalized));
    });
  }, [kevOnly, query, searchCveIds, severity, state.findings]);

  const metrics = useMemo(() => {
    const allAffected = state.findings;
    const urgent = allAffected.filter((finding) => finding.score >= 90).length;
    const kevExposures = allAffected.filter(
      (finding) => finding.vulnerability.knownExploited && finding.asset.internetFacing,
    ).length;
    const affectedAssets = new Set(allAffected.map((finding) => finding.asset.id)).size;
    const pending = state.board.filter((item) => item.status === 'proposed').length;
    return { urgent, kevExposures, affectedAssets, pending };
  }, [state.board, state.findings]);

  async function runGuidedWorkflow() {
    if (state.workflowStatus === 'running') return;
    patchPilotStore.startWorkflow();
    await wait(350);

    patchPilotStore.updateStage('search', 'running', state.context.riskPosture === 'aggressive' ? 'Filtering to known exploitation' : 'Reviewing high-risk public records');
    const searchResult = patchPilotStore.search({ limit: 50 });
    await wait(650);
    patchPilotStore.updateStage('search', 'complete', `${searchResult.total} public records in scope`);

    patchPilotStore.updateStage('match', 'running', 'Correlating explicit product versions');
    const findings = patchPilotStore.findAffected({
      cveIds: searchResult.vulnerabilities.map((vulnerability) => vulnerability.cveId),
      internetFacingOnly: state.context.internetFacingOnly,
    });
    await wait(650);
    patchPilotStore.updateStage('match', 'complete', `${findings.length} ${state.context.internetFacingOnly ? 'exposed' : 'in-scope'} asset matches`);

    patchPilotStore.updateStage('prioritize', 'running', 'Scoring severity, exploitation, exposure, and criticality');
    const prioritized = patchPilotStore.prioritize({
      findingIds: findings.map((finding) => finding.id),
      limit: 3,
    });
    await wait(700);
    patchPilotStore.updateStage('prioritize', 'complete', `Top ${prioritized.length} selected · ${prioritized[0]?.score ?? 0} peak risk`);

    patchPilotStore.updateStage('plan', 'running', 'Sequencing ownership and due dates');
    const created = patchPilotStore.createPlan({
      findingIds: prioritized.map((finding) => finding.id),
      count: 3,
      windowDays: state.context.remediationWindowDays,
      objective: state.context.focus,
    });
    await wait(650);
    patchPilotStore.updateStage('plan', 'complete', `${created.length} proposals staged for review`);
    patchPilotStore.completeWorkflow();
    await wait(200);
    boardRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  async function refreshData() {
    setRefreshing(true);
    const result = await patchPilotStore.refreshData();
    setRefreshNotice(result.ok
      ? { tone: 'success', text: `Live CISA KEV loaded · ${result.count} records` }
      : { tone: 'error', text: 'Live refresh unavailable · bundled snapshot retained' });
    setRefreshing(false);
  }

  async function copyPrompt() {
    await navigator.clipboard.writeText(demoPrompt);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1_600);
  }

  const webMcpLabel = {
    checking: 'Registering tools',
    ready: 'WebMCP ready',
    unavailable: 'UI fallback mode',
    error: 'Tool registration error',
  }[state.webMcpStatus];

  const workflowLabel = {
    idle: 'Ready',
    running: 'Working',
    complete: 'Complete',
    error: 'Needs attention',
  }[state.workflowStatus];
  const activePlanWindow = state.board.length > 0
    ? Math.max(...state.board.map((item) => item.targetDay))
    : state.context.remediationWindowDays;

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">Skip to dashboard</a>

      <aside className={`sidebar ${mobileNavOpen ? 'sidebar--open' : ''}`}>
        <div className="brand-lockup">
          <div className="brand-mark" aria-hidden="true">
            <span />
            <span />
            <span />
          </div>
          <div>
            <strong>PatchPilot</strong>
            <span>Vulnerability triage</span>
          </div>
        </div>

        <nav className="nav-list" aria-label="Primary navigation">
          <a className="nav-link nav-link--active" href="#overview" onClick={() => setMobileNavOpen(false)}>
            <LayoutDashboard size={17} /> Overview
          </a>
          <a className="nav-link" href="#findings" onClick={() => setMobileNavOpen(false)}>
            <Radar size={17} /> Findings <span className="nav-count">{state.findings.length}</span>
          </a>
          <a className="nav-link" href="#remediation" onClick={() => setMobileNavOpen(false)}>
            <ClipboardCheck size={17} /> Remediation <span className="nav-count">{state.board.length}</span>
          </a>
          <button className="nav-link" type="button" onClick={() => { setActivePanel('inventory'); setMobileNavOpen(false); }}>
            <Server size={17} /> Inventory <span className="nav-count">15</span>
          </button>
          <button className="nav-link" type="button" onClick={() => { setActivePanel('tools'); setMobileNavOpen(false); }}>
            <Zap size={17} /> Tool registry <span className="nav-count">4</span>
          </button>
        </nav>

        <div className="sidebar-spacer" />
        <div className="clean-room-note">
          <LockKeyhole size={16} />
          <div>
            <strong>Clean-room demo</strong>
            <span>Public CVEs · synthetic assets</span>
          </div>
        </div>
        <div className="sidebar-footer">
          <span className={`status-dot status-dot--${state.webMcpStatus}`} />
          <span>{webMcpLabel}</span>
        </div>
      </aside>

      {mobileNavOpen && <button className="mobile-scrim" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)} />}

      <main id="main-content" className="main-content">
        <header className="topbar">
          <div className="topbar-left">
            <button className="icon-button mobile-menu" type="button" onClick={() => setMobileNavOpen(true)} aria-label="Open navigation">
              <Menu size={20} />
            </button>
            <div className="breadcrumb">
              <span>Security operations</span>
              <ChevronDown size={14} aria-hidden="true" />
              <strong>Exposure review</strong>
            </div>
          </div>
          <div className="topbar-actions">
            <div className="data-health" title={state.dataSource.fallbackReason ?? state.dataSource.catalogVersion}>
              <Database size={15} />
              <span>{state.dataSource.mode === 'live' ? 'Live KEV' : 'Snapshot'}</span>
              <i className={`source-pulse source-pulse--${state.dataSource.mode}`} />
            </div>
            <button className="icon-button" type="button" onClick={refreshData} disabled={refreshing} aria-label="Refresh CISA KEV data">
              <RefreshCw className={refreshing ? 'spin' : ''} size={18} />
            </button>
            <button className="avatar-button" type="button" onClick={() => setActivePanel('context')} aria-label="Edit organization context">
              NC
            </button>
          </div>
        </header>

        {refreshNotice && (
          <div className={`refresh-notice refresh-notice--${refreshNotice.tone}`} role="status">
            {refreshNotice.tone === 'success' ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
            <span>{refreshNotice.text}</span>
            <button type="button" onClick={() => setRefreshNotice(null)} aria-label="Dismiss data status"><X size={14} /></button>
          </div>
        )}

        <div className="dashboard" id="overview">
          <section className="page-intro" aria-labelledby="page-title">
            <div>
              <div className="eyebrow"><span /> Exposure intelligence / {state.dataSource.snapshotDate}</div>
              <h1 id="page-title">Prioritize what attackers can reach.</h1>
              <p>{state.context.focus}. PatchPilot combines public exploitation evidence with synthetic business context—then leaves the decision with you.</p>
            </div>
            <button className="context-button" type="button" onClick={() => setActivePanel('context')}>
              <Settings2 size={16} />
              <span><small>Analysis context</small>{state.context.organizationName} · {state.context.remediationWindowDays} days</span>
              <ArrowRight size={16} />
            </button>
          </section>

          <section className="metric-strip" aria-label="Exposure summary">
            <Metric
              icon={<CircleAlert size={18} />}
              label="Urgent findings"
              value={metrics.urgent}
              detail="Risk score 90 or higher"
              tone="danger"
            />
            <Metric
              icon={<Target size={18} />}
              label="Exploited + exposed"
              value={metrics.kevExposures}
              detail="CISA KEV · internet-facing"
              tone="warning"
            />
            <Metric
              icon={<Network size={18} />}
              label="Assets in scope"
              value={metrics.affectedAssets}
              detail={`Across ${plural(inventory.length, 'synthetic asset')}`}
              tone="neutral"
            />
            <Metric
              icon={<UserCheck size={18} />}
              label="Awaiting review"
              value={metrics.pending}
              detail="Agent proposals · human gate"
              tone="success"
            />
          </section>

          <section className="analysis-grid">
            <div className="surface findings-surface" id="findings">
              <div className="surface-header">
                <div>
                  <div className="section-kicker">Prioritized exposure</div>
                  <h2>Actionable findings</h2>
                </div>
                <div className="catalog-scope" aria-live="polite">
                  {plural(state.searchResults.length, 'catalog match', 'catalog matches')} · {plural(visibleFindings.length, 'affected asset')}
                </div>
              </div>

              <div className="filter-bar">
                <label className="search-field">
                  <Search size={16} aria-hidden="true" />
                  <span className="sr-only">Filter findings</span>
                  <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter CVE, asset, service…" />
                </label>
                <label className="select-field">
                  <ListFilter size={15} aria-hidden="true" />
                  <span className="sr-only">Severity</span>
                  <select value={severity} onChange={(event) => setSeverity(event.target.value as Severity | 'all')}>
                    <option value="all">All severity</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                  </select>
                </label>
                <button className={`filter-chip ${kevOnly ? 'filter-chip--active' : ''}`} type="button" onClick={() => setKevOnly((current) => !current)} aria-pressed={kevOnly}>
                  <Zap size={14} /> CISA KEV
                </button>
              </div>

              <div className="table-wrap">
                <table className="findings-table">
                  <thead>
                    <tr>
                      <th scope="col">Rank / vulnerability</th>
                      <th scope="col">Affected asset</th>
                      <th scope="col">Signals</th>
                      <th scope="col">Risk</th>
                      <th scope="col"><span className="sr-only">Open details</span></th>
                    </tr>
                  </thead>
                  <tbody>
                    {visibleFindings.slice(0, 8).map((finding, index) => (
                      <tr key={finding.id}>
                        <td>
                          <div className="rank-cell">
                            <span className="rank-number">{String(index + 1).padStart(2, '0')}</span>
                            <div>
                              <button className="cve-link" type="button" onClick={() => setSelectedFinding(finding)}>{finding.vulnerability.cveId}</button>
                              <span>{finding.vulnerability.vendor} · {finding.vulnerability.product}</span>
                            </div>
                          </div>
                        </td>
                        <td>
                          <strong className="asset-name">{finding.asset.hostname}</strong>
                          <span className="cell-subtitle">{finding.asset.service} · {finding.asset.owner}</span>
                        </td>
                        <td>
                          <div className="signal-list">
                            {finding.vulnerability.knownExploited && <span className="signal signal--kev"><Zap size={11} /> KEV</span>}
                            {finding.asset.internetFacing && <span className="signal"><Network size={11} /> Internet</span>}
                            <span className="signal"><Gauge size={11} /> {finding.vulnerability.cvss?.toFixed(1) ?? 'N/A'}</span>
                          </div>
                        </td>
                        <td>
                          <div className={`risk-score risk-score--${scoreTone(finding.score)}`}>
                            <strong>{finding.score}</strong><span>/100</span>
                          </div>
                        </td>
                        <td>
                          <button className="row-action" type="button" onClick={() => setSelectedFinding(finding)} aria-label={`Open ${finding.vulnerability.cveId} on ${finding.asset.hostname}`}>
                            <ArrowRight size={16} />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {visibleFindings.length === 0 && (
                  <div className="empty-table">
                    <FileSearch2 size={22} />
                    <strong>No affected assets in this view</strong>
                    <span>Change the filters or run a broader catalog search.</span>
                  </div>
                )}
              </div>
            </div>

            <aside className="agent-panel" aria-labelledby="agent-panel-title">
              <div className="agent-panel-topline">
                <div className="agent-identity"><Bot size={18} /><span>Agent workspace</span></div>
                <span className={`agent-state agent-state--${state.workflowStatus}`}>
                  <i /> {workflowLabel}
                </span>
              </div>
              <h2 id="agent-panel-title">One prompt. Four visible tools.</h2>
              <div className="ownership-split" aria-label="Agent and reviewer responsibilities">
                <div><span><Bot size={14} /> Agent</span><small>Search · Match · Rank · Draft</small></div>
                <ArrowRight size={14} aria-hidden="true" />
                <div><span><UserCheck size={14} /> Reviewer</span><small>Context · Edit · Approve</small></div>
              </div>
              <div className="prompt-box">
                <Sparkles size={16} />
                <p>“{demoPrompt}”</p>
                <button type="button" onClick={copyPrompt}>{copied ? <Check size={14} /> : 'Copy'}</button>
              </div>

              <div className="workflow-stages" aria-live="polite">
                {state.workflowStages.map((stage, index) => (
                  <div className={`workflow-stage workflow-stage--${stage.status}`} key={stage.id}>
                    <div className="stage-rail">
                      <span>{stage.status === 'complete' ? <Check size={13} /> : stage.status === 'error' ? <AlertTriangle size={12} /> : index + 1}</span>
                      {index < state.workflowStages.length - 1 && <i />}
                    </div>
                    <div>
                      <strong>{stage.label}</strong>
                      <code>{stage.tool}</code>
                      <small>{stage.detail}</small>
                    </div>
                  </div>
                ))}
              </div>

              {state.workflowStatus === 'complete' && (
                <div className="run-receipt" aria-label="Completed evidence funnel">
                  <span><strong>{state.workflowSummary.searched}</strong><small>CVEs</small></span>
                  <ArrowRight size={13} />
                  <span><strong>{state.workflowSummary.matched}</strong><small>matches</small></span>
                  <ArrowRight size={13} />
                  <span><strong>{state.workflowSummary.prioritized}</strong><small>priorities</small></span>
                  <ArrowRight size={13} />
                  <span><strong>{state.workflowSummary.proposals}</strong><small>proposals</small></span>
                </div>
              )}

              <div className="agent-actions">
                <button className="primary-button primary-button--light" type="button" onClick={state.workflowStatus === 'complete' ? () => boardRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }) : runGuidedWorkflow} disabled={state.workflowStatus === 'running'}>
                  {state.workflowStatus === 'running' ? <RefreshCw className="spin" size={16} /> : state.workflowStatus === 'complete' ? <ArrowRight size={16} /> : <Play size={16} fill="currentColor" />}
                  {state.workflowStatus === 'idle' ? 'Run guided workflow' : state.workflowStatus === 'running' ? 'Running tools…' : state.workflowStatus === 'error' ? 'Retry guided workflow' : 'Review proposed plan'}
                </button>
                {(state.workflowStatus === 'complete' || state.workflowStatus === 'error') && (
                  <button className="ghost-button ghost-button--dark" type="button" onClick={() => patchPilotStore.resetDemo()}><RotateCcw size={15} /> Reset</button>
                )}
              </div>
              <p className="agent-footnote"><ShieldCheck size={14} /> The guided preview uses the same handlers exposed to WebMCP. Approval is not registered as a tool.</p>
            </aside>
          </section>

          <section className="board-section" id="remediation" ref={boardRef}>
            <div className="board-header">
              <div>
                <div className="section-kicker">Shared decision surface</div>
                <h2>{activePlanWindow}-day remediation board</h2>
                <p>Agent recommendations arrive as proposals. A person can modify, approve, and own every change.</p>
              </div>
              <div className="board-summary">
                <span><i className="legend-dot legend-dot--proposed" /> {state.board.filter((item) => item.status === 'proposed').length} proposed</span>
                <span><i className="legend-dot legend-dot--approved" /> {state.board.filter((item) => item.status === 'approved').length} approved</span>
              </div>
            </div>

            <div className="decision-firewall">
              <div className="decision-firewall-icon"><ShieldCheck size={18} /></div>
              <div><strong>Human review gate</strong><span>Tools stop at proposals. Approval is not exposed through WebMCP and requires direct review in the page.</span></div>
              <span className="human-only-badge"><UserCheck size={13} /> Not a tool</span>
            </div>

            {state.board.length === 0 ? (
              <div className="board-empty">
                <div className="board-empty-icon"><ClipboardCheck size={24} /></div>
                <div>
                  <strong>No recommendations staged yet</strong>
                  <span>Run the guided workflow or ask a compatible browser agent to call <code>create_remediation_plan</code>.</span>
                </div>
                <button className="secondary-button" type="button" onClick={runGuidedWorkflow}><Play size={15} fill="currentColor" /> Stage top three</button>
              </div>
            ) : (
              <div className="board-grid">
                {(['proposed', 'approved'] as RemediationStatus[]).map((status) => (
                  <BoardLane
                    key={status}
                    status={status}
                    items={state.board.filter((item) => item.status === status)}
                    onEdit={setEditingItem}
                    onApprove={(id) => setApprovingItem(state.board.find((item) => item.id === id) ?? null)}
                  />
                ))}
              </div>
            )}
          </section>

          <section className="audit-strip" aria-labelledby="activity-title">
            <div className="audit-heading">
              <Activity size={17} />
              <div><h2 id="activity-title">Activity trail</h2><span>Recent agent and human actions stay visible</span></div>
            </div>
            <div className="audit-events">
              {state.activity.slice(0, 4).map((event) => (
                <div className="audit-event" key={event.id}>
                  <i className={`audit-event-dot audit-event-dot--${event.kind}`} />
                  <div><strong>{event.label}</strong><span>{event.detail}</span></div>
                  <time>{event.time}</time>
                </div>
              ))}
            </div>
          </section>

          <footer className="app-footer">
            <span>PatchPilot · WebMCP Challenge clean-room prototype</span>
            <div>
              <a href={publicDataSources.cisaKevCatalog} target="_blank" rel="noreferrer">CISA KEV <ExternalLink size={12} /></a>
              <a href={publicDataSources.nvd} target="_blank" rel="noreferrer">NVD <ExternalLink size={12} /></a>
              <button type="button" onClick={() => setActivePanel('tools')}>4 WebMCP tools</button>
            </div>
          </footer>
        </div>
      </main>

      {activePanel && (
        <SidePanel type={activePanel} context={state.context} onClose={() => setActivePanel(null)} />
      )}
      {selectedFinding && <FindingDrawer finding={selectedFinding} onClose={() => setSelectedFinding(null)} />}
      {editingItem && <EditRemediationDialog item={editingItem} onClose={() => setEditingItem(null)} />}
      {approvingItem && (
        <ApproveRemediationDialog
          item={approvingItem}
          onClose={() => setApprovingItem(null)}
          onConfirm={() => {
            patchPilotStore.approveItem(approvingItem.id);
            setApprovingItem(null);
          }}
        />
      )}
    </div>
  );
}

function Metric({ icon, label, value, detail, tone }: { icon: React.ReactNode; label: string; value: number; detail: string; tone: string }) {
  return (
    <article className={`metric metric--${tone}`}>
      <div className="metric-icon">{icon}</div>
      <div><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>
    </article>
  );
}

const laneDetails: Record<RemediationStatus, { title: string; description: string }> = {
  proposed: { title: 'Proposed', description: 'Agent-created · review required' },
  approved: { title: 'Approved', description: 'Human decision recorded' },
  in_progress: { title: 'In progress', description: 'Owner is executing' },
  verified: { title: 'Verified', description: 'Evidence confirmed' },
};

function BoardLane({
  status,
  items,
  onEdit,
  onApprove,
}: {
  status: RemediationStatus;
  items: RemediationItem[];
  onEdit: (item: RemediationItem) => void;
  onApprove: (id: string) => void;
}) {
  const details = laneDetails[status];
  return (
    <div className={`board-lane board-lane--${status}`}>
      <div className="lane-heading">
        <div><strong>{details.title}</strong><span>{details.description}</span></div>
        <span className="lane-count">{items.length}</span>
      </div>
      <div className="lane-items">
        {items.map((item) => (
          <article className="remediation-card" key={item.id}>
            <div className="remediation-card-top">
              <span className={`risk-mini risk-mini--${scoreTone(item.score)}`}>{item.score}</span>
              <span className="target-day"><Clock3 size={12} /> Day {item.targetDay}</span>
              <button type="button" onClick={() => onEdit(item)} aria-label={`Edit ${item.cveId} recommendation`}><Pencil size={14} /></button>
            </div>
            <h3>{item.cveId}</h3>
            <p>{item.hostname}</p>
            <div className="remediation-meta"><span>{item.service}</span><span>{item.owner}</span></div>
            <div className="due-line"><span>Target</span><strong>{formatDate(item.dueDate)}</strong></div>
            {status === 'proposed' ? (
              <button className="approve-button" type="button" onClick={() => onApprove(item.id)}><Check size={14} /> Approve recommendation</button>
            ) : status === 'approved' ? (
              <div className="approved-label"><CheckCircle2 size={14} /> Approved by human</div>
            ) : (
              <div className="placeholder-label">No items in this demo stage</div>
            )}
          </article>
        ))}
        {items.length === 0 && <div className="lane-empty"><span />Nothing here yet</div>}
      </div>
    </div>
  );
}

function SidePanel({
  type,
  context,
  onClose,
}: {
  type: 'context' | 'inventory' | 'tools';
  context: OrganizationContext;
  onClose: () => void;
}) {
  const [draft, setDraft] = useState(context);
  const tools = buildPatchPilotTools();
  return (
    <div className="drawer-layer" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <aside className="side-drawer" role="dialog" aria-modal="true" aria-labelledby="drawer-title">
        <div className="drawer-header">
          <div>
            <span className="section-kicker">{type === 'context' ? 'Human context' : type === 'inventory' ? 'Clean-room data' : 'Agent interface'}</span>
            <h2 id="drawer-title">{type === 'context' ? 'Analysis context' : type === 'inventory' ? 'Synthetic inventory' : 'WebMCP tool registry'}</h2>
          </div>
          <button className="icon-button" type="button" onClick={onClose} aria-label="Close panel"><X size={19} /></button>
        </div>

        {type === 'context' && (
          <form
            className="context-form"
            onSubmit={(event) => {
              event.preventDefault();
              patchPilotStore.updateContext(draft);
              onClose();
            }}
          >
            <div className="form-callout"><Info size={16} /><p>This context influences scope and timing. Asset criticality remains tied to the synthetic inventory.</p></div>
            <label><span>Organization label</span><input value={draft.organizationName} maxLength={50} onChange={(event) => setDraft({ ...draft, organizationName: event.target.value })} /></label>
            <label><span>Primary objective</span><textarea rows={3} value={draft.focus} maxLength={160} onChange={(event) => setDraft({ ...draft, focus: event.target.value })} /></label>
            <fieldset>
              <legend>Risk posture</legend>
              <label className={`choice-card ${draft.riskPosture === 'aggressive' ? 'choice-card--active' : ''}`}>
                <input type="radio" name="riskPosture" checked={draft.riskPosture === 'aggressive'} onChange={() => setDraft({ ...draft, riskPosture: 'aggressive' })} />
                <Zap size={17} /><span><strong>Aggressive</strong><small>Prioritize active exploitation and public exposure</small></span>
              </label>
              <label className={`choice-card ${draft.riskPosture === 'balanced' ? 'choice-card--active' : ''}`}>
                <input type="radio" name="riskPosture" checked={draft.riskPosture === 'balanced'} onChange={() => setDraft({ ...draft, riskPosture: 'balanced' })} />
                <Gauge size={17} /><span><strong>Balanced</strong><small>Review all affected assets in ranked order</small></span>
              </label>
            </fieldset>
            <label className="toggle-row"><span><strong>Internet-facing scope</strong><small>Focus agent correlation on exposed systems</small></span><input type="checkbox" checked={draft.internetFacingOnly} onChange={(event) => setDraft({ ...draft, internetFacingOnly: event.target.checked })} /></label>
            <label><span>Remediation window</span><select value={draft.remediationWindowDays} onChange={(event) => setDraft({ ...draft, remediationWindowDays: Number(event.target.value) })}><option value={3}>3 days</option><option value={7}>7 days</option><option value={14}>14 days</option></select></label>
            <button className="primary-button" type="submit"><Check size={16} /> Save context</button>
          </form>
        )}

        {type === 'inventory' && (
          <div className="inventory-list">
            <div className="drawer-callout"><LockKeyhole size={16} /><span>All 15 records are fictional. No employer systems or internal data are included.</span></div>
            {inventory.map((asset) => (
              <article className="inventory-row" key={asset.id}>
                <div className="inventory-icon"><Server size={16} /></div>
                <div><strong>{asset.hostname}</strong><span>{asset.service} · {asset.software.map((item) => `${item.name} ${item.version}`).join(', ')}</span></div>
                <div className="inventory-flags">
                  {asset.internetFacing && <span><Network size={11} /> Public</span>}
                  <span>C{asset.criticality}</span>
                </div>
              </article>
            ))}
          </div>
        )}

        {type === 'tools' && (
          <div className="tool-list">
            <div className={`tool-status-card tool-status-card--${patchPilotStore.getState().webMcpStatus}`}>
              <Zap size={18} />
              <div><strong>{patchPilotStore.getState().webMcpStatus === 'ready' ? 'Four tools registered' : 'WebMCP preview not detected'}</strong><span>{patchPilotStore.getState().webMcpStatus === 'ready' ? 'document.modelContext is ready for an agent.' : 'The complete human workflow remains available in fallback mode.'}</span></div>
            </div>
            {tools.map((tool, index) => (
              <article className="tool-card" key={tool.name}>
                <div className="tool-number">0{index + 1}</div>
                <div>
                  <div className="tool-card-title"><code>{tool.name}</code><span className={tool.annotations?.readOnlyHint ? 'read-only' : 'writes-state'}>{tool.annotations?.readOnlyHint ? 'Read + focus UI' : 'Creates proposals'}</span></div>
                  <p>{tool.description}</p>
                  <div className="tool-annotations"><span><ShieldCheck size={12} /> Strict validation</span><span><AlertTriangle size={12} /> Untrusted content hint</span></div>
                </div>
              </article>
            ))}
            <div className="tool-principle"><UserCheck size={18} /><div><strong>Approval is intentionally absent</strong><span>No registered tool can approve, edit, or verify a remediation item. Those actions stay in the human interface.</span></div></div>
          </div>
        )}
      </aside>
    </div>
  );
}

function FindingDrawer({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  return (
    <div className="drawer-layer" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <aside className="side-drawer finding-drawer" role="dialog" aria-modal="true" aria-labelledby="finding-title">
        <div className="drawer-header">
          <div><span className="section-kicker">Finding detail</span><h2 id="finding-title">{finding.vulnerability.cveId}</h2></div>
          <button className="icon-button" type="button" onClick={onClose} aria-label="Close finding"><X size={19} /></button>
        </div>
        <div className="finding-hero">
          <div className={`big-score big-score--${scoreTone(finding.score)}`}><strong>{finding.score}</strong><span>risk score</span></div>
          <div><span className={`severity-label severity-label--${finding.vulnerability.severity}`}>{finding.vulnerability.severity}</span><h3>{finding.vulnerability.title}</h3><p>{finding.vulnerability.description}</p></div>
        </div>
        <section className="detail-section"><h3>Why this ranked here</h3><div className="score-breakdown">
          <ScoreRow label="CVSS severity" value={Math.round((finding.vulnerability.cvss ?? 0) * 5)} max={50} />
          <ScoreRow label="Known exploitation" value={finding.vulnerability.knownExploited ? 25 : 0} max={25} />
          <ScoreRow label="Internet exposure" value={finding.asset.internetFacing ? 15 : 0} max={15} />
          <ScoreRow label="Business criticality" value={finding.asset.criticality * 2} max={10} />
        </div><div className="tie-break-note"><Info size={14} /><span><strong>Equal-score tie-break:</strong> {finding.vulnerability.knownRansomware ? 'known ransomware use ranks this finding first' : 'no known ransomware use'}. It adds zero points.</span></div></section>
        <section className="detail-section"><h3>Affected synthetic asset</h3><dl className="detail-grid"><div><dt>Hostname</dt><dd>{finding.asset.hostname}</dd></div><div><dt>Service</dt><dd>{finding.asset.service}</dd></div><div><dt>Owner</dt><dd>{finding.asset.owner}</dd></div><div><dt>Installed</dt><dd>{finding.software.name} {finding.software.version}</dd></div></dl></section>
        <section className="detail-section"><h3>Recommended response</h3><div className="response-block"><PackageCheck size={18} /><div><strong>Upgrade to {finding.fixVersion}</strong><p>{finding.vulnerability.requiredAction}</p></div></div></section>
        <a className="source-link" href={finding.vulnerability.sourceUrl} target="_blank" rel="noreferrer">Open NVD record <ExternalLink size={14} /></a>
      </aside>
    </div>
  );
}

function ScoreRow({ label, value, max }: { label: string; value: number; max: number }) {
  return <div className="score-row"><span>{label}</span><div><i style={{ width: `${(value / max) * 100}%` }} /></div><strong>+{value}</strong></div>;
}

function ApproveRemediationDialog({
  item,
  onClose,
  onConfirm,
}: {
  item: RemediationItem;
  onClose: () => void;
  onConfirm: () => void;
}) {
  return (
    <div className="modal-layer" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <section className="edit-dialog approval-dialog" role="dialog" aria-modal="true" aria-labelledby="approval-title">
        <div className="dialog-header"><div><span className="section-kicker">Direct reviewer action</span><h2 id="approval-title">Approve {item.cveId}?</h2></div><button className="icon-button" type="button" onClick={onClose} aria-label="Close approval"><X size={18} /></button></div>
        <div className="human-gate"><UserCheck size={17} /><span>This action is not exposed through WebMCP. Confirm the evidence, owner, and target before committing.</span></div>
        <dl className="approval-summary">
          <div><dt>Risk</dt><dd>{item.score}/100</dd></div>
          <div><dt>Asset</dt><dd>{item.hostname}</dd></div>
          <div><dt>Owner</dt><dd>{item.owner}</dd></div>
          <div><dt>Target</dt><dd>{formatDate(item.dueDate)}</dd></div>
        </dl>
        <p className="approval-action">{item.action}</p>
        <div className="dialog-actions"><button className="ghost-button" type="button" onClick={onClose}>Cancel</button><button className="primary-button" type="button" onClick={onConfirm}><Check size={16} /> Confirm approval</button></div>
      </section>
    </div>
  );
}

function EditRemediationDialog({ item, onClose }: { item: RemediationItem; onClose: () => void }) {
  const [owner, setOwner] = useState(item.owner);
  const [dueDate, setDueDate] = useState(item.dueDate);
  const [action, setAction] = useState(item.action);
  const [notes, setNotes] = useState(item.notes);
  return (
    <div className="modal-layer" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <form className="edit-dialog" role="dialog" aria-modal="true" aria-labelledby="edit-title" onSubmit={(event) => { event.preventDefault(); patchPilotStore.updateItem(item.id, { owner, dueDate, action, notes }); onClose(); }}>
        <div className="dialog-header"><div><span className="section-kicker">Human modification</span><h2 id="edit-title">Edit {item.cveId}</h2></div><button className="icon-button" type="button" onClick={onClose} aria-label="Close editor"><X size={18} /></button></div>
        <div className="human-gate"><UserCheck size={17} /><span>Changes here are attributed to the human reviewer.</span></div>
        <label><span>Owner</span><input value={owner} maxLength={60} onChange={(event) => setOwner(event.target.value)} required /></label>
        <label><span>Target date</span><input type="date" value={dueDate} onChange={(event) => setDueDate(event.target.value)} required /></label>
        <label><span>Remediation action</span><textarea rows={4} value={action} maxLength={300} onChange={(event) => setAction(event.target.value)} required /></label>
        <label><span>Reviewer notes <small>optional</small></span><textarea rows={3} value={notes} maxLength={300} onChange={(event) => setNotes(event.target.value)} placeholder="Add context, dependencies, or a maintenance window…" /></label>
        <div className="dialog-actions"><button className="ghost-button" type="button" onClick={onClose}>Cancel</button><button className="primary-button" type="submit"><Check size={16} /> Save changes</button></div>
      </form>
    </div>
  );
}

export default App;
