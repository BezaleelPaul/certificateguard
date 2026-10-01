export type UserRole = 'STUDENT' | 'TEACHER' | 'ADMIN';

export type SubmissionStatus = 'PROCESSING' | 'VERIFIED' | 'REVIEW' | 'FAILED' | 'UNVERIFIABLE' | 'ERROR';

export type AnomalySeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type DuplicateMatchType = 'EXACT_HASH' | 'PERCEPTUAL_SIMILARITY' | 'CERTIFICATE_ID' | 'OCR_SIMILARITY';

export type TeacherDecision = 'APPROVE' | 'REJECT' | 'REQUEST_EVIDENCE';

export interface User {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  student_id?: string;
  created_at?: string;
}

export interface Student {
  id: string;
  student_identifier: string;
  full_name: string;
  email: string;
  department: string;
  section: string;
}

export interface ExtractedCertificateData {
  id: string;
  recipient_name?: string;
  issuer_name?: string;
  certificate_id?: string;
  course_name?: string;
  issue_date?: string;
  expiry_date?: string;
  qr_url?: string;
  raw_ocr_text?: string;
  extraction_confidence: number;
}

export interface IssuerVerification {
  id: string;
  issuer_id?: string;
  verification_method: string;
  verification_url?: string;
  certificate_id_submitted?: string;
  certificate_id_returned?: string;
  recipient_returned?: string;
  course_returned?: string;
  status_returned?: string;
  raw_evidence?: string;
  verification_status: string;
  verified_at?: string;
  error_message?: string;
}

export interface Anomaly {
  id: string;
  type: string;
  severity: AnomalySeverity;
  title: string;
  description: string;
  evidence?: string;
  confidence: number;
  created_at: string;
}

export interface DuplicateMatch {
  id: string;
  matched_submission_id: string;
  match_type: DuplicateMatchType;
  similarity: number;
  evidence?: string;
  created_at: string;
}

export interface VerificationResult {
  id: string;
  issuer_verification: string;
  identity_verification: string;
  qr_verification: string;
  certificate_id_verification: string;
  document_integrity: string;
  duplicate_check: string;
  anomaly_check: string;
  synthetic_media_signal: string;
  final_status: SubmissionStatus;
  confidence: number;
  reason_summary?: string;
  created_at: string;
  updated_at: string;
}

export interface TeacherReview {
  id: string;
  teacher_id: string;
  teacher_name?: string;
  decision: TeacherDecision;
  reason?: string;
  notes?: string;
  created_at: string;
}

export interface Submission {
  id: string;
  student_id: string;
  student?: Student;
  original_filename: string;
  stored_filename: string;
  mime_type: string;
  file_size: number;
  sha256: string;
  uploaded_at: string;
  status: SubmissionStatus;
  processing_started_at?: string;
  processing_completed_at?: string;
  extracted_data?: ExtractedCertificateData;
  issuer_verifications: IssuerVerification[];
  anomalies: Anomaly[];
  duplicate_matches: DuplicateMatch[];
  verification_result?: VerificationResult;
  reviews: TeacherReview[];
}

export interface Issuer {
  id: string;
  name: string;
  official_domain: string;
  verification_type: string;
  verification_url?: string;
  active: boolean;
  configuration_json?: string;
  created_at: string;
  updated_at: string;
}

export interface AuditLog {
  id: string;
  actor_user_id?: string;
  actor_name?: string;
  action: string;
  entity_type: string;
  entity_id: string;
  old_value?: string;
  new_value?: string;
  ip_hash?: string;
  created_at: string;
}

export interface PlatformStats {
  total_submissions: number;
  processing: number;
  verified: number;
  needs_review: number;
  failed: number;
  unverifiable: number;
  total_issuers: number;
  active_students: number;
}
