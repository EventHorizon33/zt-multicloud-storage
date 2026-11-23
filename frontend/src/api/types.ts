// Shapes from docs/API.md. Kept literal so a contract drift shows up as a type error.

export type Role = "user" | "auditor" | "admin";
export type Classification = "public" | "internal" | "confidential" | "restricted";
export const CLASSIFICATIONS: Classification[] = ["public", "internal", "confidential", "restricted"];

export interface User {
  id: string;
  username: string;
  role: Role;
  clearance: Classification;
  is_active: boolean;
  mfa_enabled: boolean;
  created_at: string;
}

/** POST /api/auth/register: always 202 with this body (F3, no enumeration). */
export interface RegisterAccepted {
  status: "accepted";
}

export interface Session {
  id: string;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  mfa_verified: boolean;
  current: boolean;
}

export interface TokenResponse {
  access_token: string;
  token_type: "bearer";
  expires_in: number;
  session_id: string;
  mfa_verified: boolean;
  user: User;
}

export interface Me {
  user: User;
  session: Session;
  audit_pseudonym: string;
  restricted: boolean;
  mfa_fresh: boolean;
}

export type FileStatus = "pending" | "uploading" | "committed" | "failed" | "deleting" | "deleted";

export interface FileRow {
  id: string;
  filename: string | null;
  mime_type: string | null;
  size_bytes: number;
  classification: Classification;
  status: FileStatus;
  chunk_count: number;
  chunk_size: number;
  created_at: string;
  committed_at: string | null;
  owner_id: string;
  owner_username: string | null;
  is_owner: boolean;
  shared_with_me: boolean;
  failure_reason: string | null;
  metadata_error: string | null;
}

export interface FileList {
  files: FileRow[];
  total: number;
}

export interface AdminFileList extends FileList {
  limit: number;
  offset: number;
  scope: "all" | "own";
}

export interface Share {
  username: string;
  created_at: string;
}

export type ReplicaResult = "ok" | "corrupt" | "missing" | "unavailable";
export interface VerifyReport {
  file_id: string;
  healthy: boolean;
  recoverable: boolean;
  summary: { ok: number; corrupt: number; missing: number; unavailable: number };
  chunks: { index: number; chunk_id: string; replicas: { provider: string; result: ReplicaResult }[] }[];
}

export interface RepairReport {
  file_id: string;
  ok: boolean;
  repaired_chunks: number[];
  unrepairable_chunks: number[];
}

export type ReplicaStatus = "pending" | "stored" | "failed" | "missing" | "corrupt" | "deleted";
export interface FileDistribution {
  file_id: string;
  status: FileStatus;
  chunk_count: number;
  replication_factor: number;
  providers: Record<string, number>;
  chunks: {
    index: number;
    chunk_id: string;
    ciphertext_size: number;
    ciphertext_sha256: string;
    replicas: {
      provider: string;
      status: ReplicaStatus;
      stored_at: string | null;
      last_verified_at: string | null;
    }[];
  }[];
}

export interface ProviderHealth {
  provider: string;
  kind: string;
  healthy: boolean | null;
  state: "closed" | "open" | "half-open";
  latency_ms: number | null;
  consecutive_failures: number;
  last_checked: string | null;
  last_error: string | null;
  total_successes: number;
  total_failures: number;
  injected: boolean;
  fault_mode: string | null;
}

export interface ProvidersResponse {
  providers: ProviderHealth[];
  replication_factor: number;
  min_write_replicas: number;
  fault_injection_enabled: boolean;
}

export interface ProviderDistribution {
  replicas: number;
  bytes: number;
  by_status: Record<string, number>;
}

export interface StorageDistribution {
  scope: "all" | "own";
  files: number;
  bytes: number;
  chunks: number;
  files_by_status: Record<FileStatus, number>;
  distribution: Record<string, ProviderDistribution>;
}

export interface OpCounter {
  attempts: number;
  successes: number;
  failures: number;
  retries: number;
  bytes: number;
}
export interface StorageMetrics {
  counters: Record<string, Record<string, OpCounter>>;
  latency: Record<string, Record<string, { count: number; sum_seconds: number; buckets: Record<string, number> }>>;
}

export const FAULT_MODES = ["none", "unavailable", "timeout", "corrupt-reads", "fail-n", "drop-writes", "slow"] as const;
export type FaultMode = (typeof FAULT_MODES)[number];
export interface FaultStatus {
  provider: string;
  mode: string;
  params: Record<string, unknown>;
  remaining_failures: number | null;
  injected: boolean;
  fault_injection_enabled: boolean;
  injected_failures_total: number;
}

export type Outcome = "success" | "failure" | "denied" | "error";
export type Severity = "info" | "warning" | "critical";

export interface AuditEvent {
  seq: number;
  id: string;
  ts: string;
  event_type: string;
  action: string | null;
  outcome: Outcome;
  severity: Severity;
  actor: string | null;
  actor_role: string | null;
  resource_type: string | null;
  resource_id: string | null;
  reason: string | null;
  details: Record<string, unknown>;
  request_id: string | null;
  source_net: string | null;
  prev_hash: string;
  hash: string;
}

export interface AuditSearch {
  events: AuditEvent[];
  total: number;
  limit: number;
  offset: number;
  scope: "all" | "own";
}

export interface VerifyChainReport {
  ok: boolean;
  events_checked: number;
  first_seq: number | null;
  last_seq: number | null;
  head_hash: string | null;
  checkpoints_checked: number;
  anchors_checked: number;
  findings: { type: string; seq: number | null; detail: string | null }[];
  findings_truncated: boolean;
  duration_ms: number;
}

export interface Checkpoint {
  id: string;
  seq: number;
  head_hash: string;
  ts: string;
  kind: string;
  key_id: string;
  key_version: number;
  signature: string;
  event_count: number;
  first_seq: number;
  anchors: Record<string, boolean>;
}

export interface Dashboard {
  scope: "all" | "own";
  generated_at: string;
  files: { count: number; bytes: number; chunks: number; by_status: Record<FileStatus, number> };
  distribution: Record<string, ProviderDistribution>;
  operations: {
    by_outcome: Record<Outcome, number>;
    total: number;
    by_event_prefix: Record<string, number> | null;
  };
  recent_security_events: AuditEvent[];
  providers: ProviderHealth[];
  providers_available: number;
  providers_total: number;
}

export interface PolicyConfig {
  mfa_required_actions: string[];
  mfa_required_classification: Classification;
  mfa_step_up_max_age_seconds: number;
  max_session_age_seconds: number;
  require_mfa_for_login: boolean;
  max_downloads_in_window: number;
  max_download_bytes_in_window: number;
  window_seconds: number;
  block_seconds: number;
}

export interface PolicyRule {
  id: string;
  description: string;
  effect: "allow" | "deny";
  stage: "guard" | "constraint" | "allow";
  actions: string[] | "*";
  roles: string[];
  condition: string | null;
  reason: string | null;
}

export interface PoliciesResponse {
  rules: PolicyRule[];
  config: PolicyConfig;
  version: number;
  ignored_keys: string[];
}

export interface PolicySettings {
  config: PolicyConfig;
  defaults: PolicyConfig;
  version: number;
  ignored_keys: string[];
}

export interface AnomalyBlock {
  blocked_until: string;
  reason: string;
  actor: string;
  user_id?: string;
  username?: string;
}

export interface AdminUser {
  id: string;
  username: string;
  role: Role;
  clearance: Classification;
  is_active: boolean;
  mfa_enabled: boolean;
  allowed_cidrs: string[];
  created_at: string;
  locked_until: string | null;
  active_sessions: number;
}

/** GET /api/security/events. `critical` is selected separately (newest CRITICAL events) so that a flood of
 *  lower-severity events cannot push a critical alert out of the feed. */
export interface SecurityEventsResponse {
  events: AuditEvent[];
  critical: AuditEvent[];
  scope: "all" | "own";
}

export interface MfaEnrollmentCode {
  user_id: string;
  enrollment_code: string;
  expires_at: string;
  single_use: true;
}

export interface KmsKey {
  purpose: string;
  key_id: string;
  version: number;
  algorithm: string;
  created_at: string;
  state: "active" | "decrypt-only" | "retired";
}

export const KMS_PURPOSES = [
  "file-dek-wrap",
  "secret-encryption",
  "token-signing",
  "audit-signing",
  "audit-pseudonym",
  "lookup-hmac",
] as const;
