// Core Types
export interface User {
  id: number;
  email: string;
  full_name: string;
  role: UserRole;
  is_active: boolean;
  is_verified: boolean;
  oauth_provider?: string;
  avatar_url?: string;
  last_login_at?: string;
  created_at: string;
  updated_at: string;
  timezone: string;
  mfa_enabled: boolean;
}

export enum UserRole {
  ADMIN = 'admin',
  SECURITY_ANALYST = 'security_analyst',
  COMPLIANCE_OFFICER = 'compliance_officer',
  USER = 'user',
  READ_ONLY = 'read_only'
}

export interface Integration {
  id: number;
  user_id: number;
  platform: Platform;
  platform_user_id: string;
  platform_username: string;
  access_token: string;
  refresh_token?: string;
  token_expires_at?: string;
  permissions: string[];
  is_active: boolean;
  last_sync: string;
  sync_status: SyncStatus;
  created_at: string;
  updated_at: string;
}

export enum Platform {
  GOOGLE_WORKSPACE = 'google_workspace',
  MICROSOFT_365 = 'microsoft_365',
  SLACK = 'slack',
  GITHUB = 'github',
  NOTION = 'notion'
}

export enum SyncStatus {
  PENDING = 'pending',
  IN_PROGRESS = 'in_progress',
  COMPLETED = 'completed',
  FAILED = 'failed'
}

export interface Finding {
  id: number;
  integration_id: number;
  resource_type: string;
  resource_id: string;
  title: string;
  description: string;
  severity: Severity;
  category: string;
  recommendation: string;
  status: FindingStatus;
  metadata: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export enum Severity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

export enum FindingStatus {
  OPEN = 'open',
  IN_PROGRESS = 'in_progress',
  RESOLVED = 'resolved',
  DISMISSED = 'dismissed'
}

export interface Alert {
  id: number;
  user_id: number;
  finding_id?: number;
  type: AlertType;
  title: string;
  message: string;
  severity: Severity;
  is_read: boolean;
  metadata: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export enum AlertType {
  SECURITY_FINDING = 'security_finding',
  INTEGRATION_ERROR = 'integration_error',
  COMPLIANCE_VIOLATION = 'compliance_violation',
  SYSTEM_NOTIFICATION = 'system_notification'
}

export interface Scan {
  id: number;
  integration_id: number;
  platform: Platform;
  scan_type: string;
  status: ScanStatus;
  started_at: string;
  completed_at?: string;
  findings_count: number;
  metadata: Record<string, any>;
}

export enum ScanStatus {
  PENDING = 'pending',
  RUNNING = 'running',
  COMPLETED = 'completed',
  FAILED = 'failed',
  CANCELLED = 'cancelled'
}

// API Response Types
export interface ApiResponse<T> {
  data: T;
  message?: string;
  status: number;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

export interface ListResponse<T> extends ApiResponse<PaginatedResponse<T>> {}

// Dashboard Types
export interface DashboardStats {
  total_integrations: number;
  active_integrations: number;
  total_findings: number;
  critical_findings: number;
  security_score: number;
  compliance_score: number;
  last_scan?: string;
}

export interface SecurityMetrics {
  score: number;
  trend: 'up' | 'down' | 'stable';
  findings_by_severity: Record<Severity, number>;
  findings_by_platform: Record<Platform, number>;
  recent_findings: Finding[];
}

export interface ComplianceStatus {
  overall_score: number;
  frameworks: Array<{
    name: string;
    score: number;
    status: 'compliant' | 'partial' | 'non_compliant';
    findings_count: number;
  }>;
}

// Authentication Types
export interface LoginCredentials {
  email: string;
  password: string;
}

export interface RegisterCredentials extends LoginCredentials {
  full_name: string;
  confirm_password: string;
}

export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface AuthState {
  user: User | null;
  tokens: AuthTokens | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
}

// Form Types
export interface UserCreateForm {
  email: string;
  password: string;
  full_name: string;
  role: UserRole;
  timezone: string;
  send_welcome_email: boolean;
}

export interface UserUpdateForm {
  full_name?: string;
  role?: UserRole;
  is_active?: boolean;
  timezone?: string;
  notification_preferences?: Record<string, any>;
}

export interface PasswordChangeForm {
  current_password: string;
  new_password: string;
  confirm_password: string;
}

// UI Types
export interface NotificationState {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  title: string;
  message: string;
  duration?: number;
  actions?: Array<{
    label: string;
    action: () => void;
  }>;
}

export interface TableColumn {
  id: string;
  label: string;
  minWidth?: number;
  align?: 'left' | 'right' | 'center';
  format?: (value: any) => string;
  sortable?: boolean;
}

export interface FilterState {
  search?: string;
  platform?: Platform;
  severity?: Severity;
  status?: string;
  date_from?: string;
  date_to?: string;
}

// WebSocket Types
export interface WebSocketMessage {
  type: string;
  data: any;
  timestamp: string;
}

export interface RealtimeUpdate {
  entity_type: 'finding' | 'integration' | 'scan' | 'alert';
  entity_id: number;
  action: 'created' | 'updated' | 'deleted';
  data: any;
}

// Theme Types
export interface ThemeSettings {
  mode: 'light' | 'dark';
  primaryColor: string;
  fontSize: 'small' | 'medium' | 'large';
  density: 'compact' | 'comfortable' | 'spacious';
}

// Navigation Types
export interface NavigationItem {
  id: string;
  label: string;
  icon: string;
  path: string;
  permissions?: string[];
  children?: NavigationItem[];
  badge?: {
    count: number;
    color: 'primary' | 'secondary' | 'error' | 'warning' | 'info' | 'success';
  };
}

// Error Types
export interface ApiError {
  message: string;
  code?: string;
  status?: number;
  details?: Record<string, any>;
}

export interface ValidationError {
  field: string;
  message: string;
}

// Export utility types
export type Optional<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;
export type RequireOnly<T, K extends keyof T> = Pick<T, K> & Partial<Omit<T, K>>;
export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

export type ID = string | number;
export type Timestamp = string;
export type JSONValue = string | number | boolean | null | JSONValue[] | { [key: string]: JSONValue };