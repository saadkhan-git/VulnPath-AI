export type SeverityLevel = "critical" | "high" | "medium" | "low" | "info";
export type ScanStatus =
  | "pending"
  | "extracting"
  | "parsing"
  | "analyzing"
  | "fusing"
  | "completed"
  | "failed"
  | "cancelled";
export type ReportFormat = "json" | "sarif" | "markdown";

export interface HealthResponse {
  status: string;
  product: {
    name: string;
    tagline: string;
    version: string;
    creator: string;
    github: string;
  };
  governance: {
    clean_room_verified: boolean;
    license: string;
  };
  runtime: {
    python_version: string;
    platform: string;
  };
  capabilities: {
    supported_extensions: string[];
    max_file_count: number;
    max_archive_size_mb: number;
    max_single_file_mb: number;
  };
}

export interface CodePathNode {
  step_number: number;
  file_path: string;
  line_number: number;
  function_name?: string | null;
  statement: string;
  node_type: string;
  description?: string | null;
}

export interface Finding {
  finding_id: string;
  scan_id: string;
  title: string;
  cwe_id: string;
  file_path: string;
  line_number: number;
  end_line_number?: number | null;
  function_name?: string | null;
  severity: SeverityLevel;
  confidence: number;
  reachability: string;
  exposure: string;
  remediation_priority: string;
  source_description?: string | null;
  sink_description?: string | null;
  evidence_notes: string[];
  analysis_sources: string[];
  code_context?: string | null;
  data_flow_path: CodePathNode[];
  status: string;
  created_at: string;
}

export interface ScanConfig {
  project_name: string;
  enable_bandit: boolean;
  enable_taint_analysis: boolean;
  context_lines: number;
}

export interface ScanSummary {
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  security_score: number;
  cwe_distribution: Record<string, number>;
}

export interface ScanRead {
  scan_id: string;
  project_name: string;
  target_type: string;
  status: ScanStatus;
  progress_percent: number;
  current_file?: string | null;
  files_scanned: number;
  total_files: number;
  summary: ScanSummary;
  error_message?: string | null;
  created_at: string;
  completed_at?: string | null;
  findings?: Finding[] | null;
}

export interface ScanStart {
  scan_id: string;
  status: ScanStatus;
  files_queued?: number;
}

export interface ReportFormatOption {
  value: ReportFormat;
  label: string;
}
