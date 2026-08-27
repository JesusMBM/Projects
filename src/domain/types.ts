export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';
export type Criticality = 1 | 2 | 3 | 4 | 5;
export type AssetEnvironment = 'production' | 'corporate' | 'development';
export type RemediationStatus = 'proposed' | 'approved' | 'in_progress' | 'verified';

export interface SoftwareInstall {
  productId: string;
  name: string;
  version: string;
}

export interface Asset {
  id: string;
  hostname: string;
  service: string;
  owner: string;
  environment: AssetEnvironment;
  internetFacing: boolean;
  criticality: Criticality;
  instanceCount?: number;
  software: SoftwareInstall[];
}

export interface AffectedProduct {
  productId: string;
  versions: string[];
  fixVersion: string;
}

export interface Vulnerability {
  cveId: string;
  vendor: string;
  product: string;
  title: string;
  description: string;
  cvss: number | null;
  severity: Severity;
  knownExploited: boolean;
  knownRansomware: boolean;
  dateAdded: string | null;
  cisaDueDate: string | null;
  published: string;
  requiredAction: string;
  sourceUrl: string;
  affectedProducts: AffectedProduct[];
}

export interface Finding {
  id: string;
  vulnerability: Vulnerability;
  asset: Asset;
  software: SoftwareInstall;
  fixVersion: string;
  score: number;
  tier: 'urgent' | 'high' | 'guarded' | 'routine';
  scoreSignals: string[];
}

export interface RemediationItem {
  id: string;
  findingId: string;
  cveId: string;
  assetId: string;
  hostname: string;
  service: string;
  owner: string;
  status: RemediationStatus;
  dueDate: string;
  targetDay: number;
  action: string;
  validation: string;
  rationale: string;
  notes: string;
  score: number;
  createdAt: string;
  approvedAt: string | null;
}

export interface OrganizationContext {
  organizationName: string;
  focus: string;
  riskPosture: 'balanced' | 'aggressive';
  internetFacingOnly: boolean;
  remediationWindowDays: number;
}

export interface SearchInput {
  query?: string;
  severity?: Severity;
  knownExploitedOnly?: boolean;
  minCvss?: number;
  limit?: number;
}

export interface SearchResult {
  vulnerabilities: Vulnerability[];
  total: number;
}

export interface AffectedAssetsInput {
  cveIds?: string[];
  internetFacingOnly?: boolean;
}

export interface PrioritizeInput extends AffectedAssetsInput {
  limit?: number;
}

export interface PlanInput {
  findingIds?: string[];
  count?: number;
  windowDays?: number;
  objective?: string;
}

export interface ActivityEvent {
  id: string;
  time: string;
  label: string;
  detail: string;
  kind: 'data' | 'tool' | 'human' | 'system';
}

export interface DataSourceStatus {
  mode: 'bundled' | 'live';
  label: string;
  snapshotDate: string;
  catalogVersion: string;
  lastChecked: string | null;
  fallbackReason: string | null;
}

export interface WorkflowStage {
  id: 'search' | 'match' | 'prioritize' | 'plan';
  label: string;
  tool: string;
  status: 'pending' | 'running' | 'complete';
  detail: string;
}

export interface PatchPilotState {
  context: OrganizationContext;
  vulnerabilities: Vulnerability[];
  searchResults: Vulnerability[];
  findings: Finding[];
  board: RemediationItem[];
  activity: ActivityEvent[];
  dataSource: DataSourceStatus;
  webMcpStatus: 'checking' | 'ready' | 'unavailable' | 'error';
  workflowStatus: 'idle' | 'running' | 'complete';
  workflowStages: WorkflowStage[];
}
