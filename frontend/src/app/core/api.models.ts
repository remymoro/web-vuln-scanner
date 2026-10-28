export interface Credentials {
  email: string;
  password: string;
}

export interface User {
  id: string;
  email: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
}

export interface DnsRecord {
  type: 'TXT';
  name: string;
  value: string;
}

export interface Target {
  id: string;
  domain: string;
  verified: boolean;
  verified_at: string | null;
  dns_record: DnsRecord;
}

export type ScanStatus = 'pending' | 'running' | 'done' | 'failed';
export type Grade = 'A' | 'B' | 'C' | 'D' | 'E';
export type Severity = 'high' | 'medium' | 'low' | 'info';

export interface RequestedScan {
  id: string;
  status: ScanStatus;
}

export interface Scan extends RequestedScan {
  target_id: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  score: number | null;
  grade: Grade | null;
  error: string | null;
}

export interface Deduction {
  finding_id: string;
  category: string;
  severity: Severity;
  points: number;
}

export interface CategoryScore {
  category: string;
  score: number;
  grade: Grade;
  deductions: Deduction[];
}

export interface Finding {
  id: string;
  scanner: string;
  category: string;
  severity: Severity;
  title: string;
  description: string;
  evidence: string;
  recommendation: string;
}

export interface ScanReport {
  score: number;
  grade: Grade;
  categories: CategoryScore[];
  deductions: Deduction[];
  findings: Finding[];
}
