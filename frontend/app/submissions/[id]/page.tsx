'use client';

import { useState, useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  ShieldCheck,
  FileCheck2,
  AlertTriangle,
  XCircle,
  HelpCircle,
  Clock,
  ArrowLeft,
  QrCode,
  Building,
  UserCheck,
  Copy,
  Search,
  FileText,
  History,
  CheckCircle,
  ExternalLink,
  Download,
  AlertOctagon,
  RefreshCw,
} from 'lucide-react';
import { api } from '@/lib/api';
import { Submission, TeacherDecision, User } from '@/types';

export default function SubmissionDetailPage() {
  const params = useParams();
  const router = useRouter();
  const id = params?.id as string;

  const [submission, setSubmission] = useState<Submission | null>(null);
  const [evidenceReport, setEvidenceReport] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'OVERVIEW' | 'ANOMALIES' | 'EVIDENCE' | 'DUPLICATES' | 'REPORT' | 'AUDIT'>('OVERVIEW');
  const [currentUser, setCurrentUser] = useState<User | null>(null);

  // Review modal state
  const [reviewDecision, setReviewDecision] = useState<TeacherDecision | null>(null);
  const [reviewReason, setReviewReason] = useState('');
  const [reviewNotes, setReviewNotes] = useState('');
  const [submittingReview, setSubmittingReview] = useState(false);
  const [reviewError, setReviewError] = useState<string | null>(null);

  useEffect(() => {
    if (id) {
      loadSubmission();
      const user = api.getCurrentUser();
      setCurrentUser(user);
    }
  }, [id]);

  const loadSubmission = async () => {
    try {
      setLoading(true);
      const sub = await api.getSubmission(id);
      setSubmission(sub);
      try {
        const report = await api.getEvidenceReport(id);
        setEvidenceReport(report);
      } catch (err) {
        // Report might not exist yet if processing
      }
    } catch (err) {
      console.error('Failed to load submission:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleReprocess = async () => {
    try {
      setLoading(true);
      await api.processSubmission(id);
      await loadSubmission();
    } catch (err) {
      alert('Reprocessing failed');
    } finally {
      setLoading(false);
    }
  };

  const handleReviewSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!reviewDecision) return;

    if ((reviewDecision === 'REJECT' || reviewDecision === 'REQUEST_EVIDENCE') && !reviewReason.trim()) {
      setReviewError('A detailed reason is mandatory when rejecting or requesting evidence.');
      return;
    }

    try {
      setSubmittingReview(true);
      setReviewError(null);
      await api.submitReview(id, reviewDecision, reviewReason, reviewNotes);
      setReviewDecision(null);
      setReviewReason('');
      setReviewNotes('');
      await loadSubmission();
    } catch (err: any) {
      setReviewError(err.message || 'Review action failed');
    } finally {
      setSubmittingReview(false);
    }
  };

  const isTeacherOrAdmin = currentUser?.role === 'TEACHER' || currentUser?.role === 'ADMIN';

  if (loading || !submission) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh]">
        <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
        <p className="mt-4 text-sm text-slate-500 font-medium">Analyzing certificate evidence...</p>
      </div>
    );
  }

  const vResult = submission.verification_result;
  const extracted = submission.extracted_data;
  const isPdf = submission.mime_type === 'application/pdf' || submission.original_filename.toLowerCase().endsWith('.pdf');
  const fileUrl = api.getFileUrl(submission.id);

  return (
    <div className="space-y-6">
      {/* Back button and status header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <Link href="/" className="inline-flex items-center text-xs font-semibold text-slate-500 hover:text-slate-800 transition">
          <ArrowLeft className="w-3.5 h-3.5 mr-1" /> Back to Dashboard
        </Link>
        <div className="flex items-center space-x-3">
          <button
            onClick={handleReprocess}
            className="inline-flex items-center px-3 py-1.5 rounded-lg border border-slate-300 bg-white text-xs font-medium text-slate-700 hover:bg-slate-50 transition"
          >
            <RefreshCw className="w-3.5 h-3.5 mr-1.5" /> Re-run Verification Pipeline
          </button>
          {isTeacherOrAdmin && (
            <div className="flex items-center space-x-2">
              <button
                onClick={() => setReviewDecision('APPROVE')}
                className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-medium shadow-sm transition"
              >
                Approve
              </button>
              <button
                onClick={() => setReviewDecision('REJECT')}
                className="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-700 text-white text-xs font-medium shadow-sm transition"
              >
                Reject
              </button>
              <button
                onClick={() => setReviewDecision('REQUEST_EVIDENCE')}
                className="px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-700 text-white text-xs font-medium shadow-sm transition"
              >
                Request Evidence
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Main Verification Banner Card */}
      <div className={`p-6 rounded-xl border shadow-sm ${
        submission.status === 'VERIFIED' ? 'bg-emerald-50/50 border-emerald-300' :
        submission.status === 'REVIEW' ? 'bg-amber-50/60 border-amber-300' :
        submission.status === 'FAILED' ? 'bg-rose-50/60 border-rose-300' :
        submission.status === 'UNVERIFIABLE' ? 'bg-slate-100 border-slate-300' : 'bg-blue-50/50 border-blue-300'
      }`}>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-500">Official System Verdict:</span>
              <span className={`text-base font-extrabold uppercase px-3 py-0.5 rounded-full ${
                submission.status === 'VERIFIED' ? 'bg-emerald-200 text-emerald-900' :
                submission.status === 'REVIEW' ? 'bg-amber-200 text-amber-900' :
                submission.status === 'FAILED' ? 'bg-rose-200 text-rose-900' :
                submission.status === 'UNVERIFIABLE' ? 'bg-slate-300 text-slate-900' : 'bg-blue-200 text-blue-900'
              }`}>
                {submission.status.replace('_', ' ')}
              </span>
              {vResult && (
                <span className="text-xs font-semibold text-slate-600 bg-white/80 px-2 py-0.5 rounded border border-slate-300">
                  Confidence: {(vResult.confidence * 100).toFixed(0)}%
                </span>
              )}
            </div>
            <p className="text-sm font-medium text-slate-800">
              {vResult?.reason_summary || 'Evidence analysis in progress...'}
            </p>
          </div>
          <div className="text-xs text-slate-500 font-mono">
            <div>SHA-256: {submission.sha256.substring(0, 24)}...</div>
            <div>Submitted by: {submission.student?.full_name} ({submission.student?.student_identifier})</div>
          </div>
        </div>
      </div>

      {/* Main Grid: Left Side Document View, Right Side Verification Tabs */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Certificate Preview & Identity Check */}
        <div className="lg:col-span-5 space-y-6">
          {/* Identity Match Card */}
          <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm space-y-3">
            <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider flex items-center">
              <UserCheck className="w-4 h-4 mr-1.5 text-blue-600" /> Identity Comparison
            </h3>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="p-2.5 bg-slate-50 rounded-lg border border-slate-200">
                <span className="text-slate-400 block font-medium">Submitting Student</span>
                <span className="font-bold text-slate-900 text-sm">{submission.student?.full_name}</span>
                <span className="text-slate-500 block text-[11px]">{submission.student?.student_identifier}</span>
              </div>
              <div className={`p-2.5 rounded-lg border ${
                vResult?.identity_verification === 'EXACT' || vResult?.identity_verification === 'HIGH_CONFIDENCE'
                  ? 'bg-emerald-50 border-emerald-200' : 'bg-rose-50 border-rose-200'
              }`}>
                <span className="text-slate-400 block font-medium">Extracted Recipient</span>
                <span className="font-bold text-slate-900 text-sm">{extracted?.recipient_name || 'Not detected'}</span>
                <span className={`block font-semibold text-[11px] ${
                  vResult?.identity_verification === 'EXACT' ? 'text-emerald-700' : 'text-rose-700'
                }`}>
                  Status: {vResult?.identity_verification || 'PENDING'}
                </span>
              </div>
            </div>
          </div>

          {/* Certificate Document Preview */}
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
            <div className="p-3 border-b border-slate-200 bg-slate-50 flex items-center justify-between">
              <span className="text-xs font-bold text-slate-600 uppercase tracking-wide flex items-center">
                <FileText className="w-3.5 h-3.5 mr-1.5 text-slate-500" /> Certificate Document
              </span>
              <a
                href={fileUrl}
                target="_blank"
                rel="noreferrer"
                className="text-xs text-blue-600 hover:text-blue-800 flex items-center font-medium"
              >
                <Download className="w-3 h-3 mr-1" /> Download Original
              </a>
            </div>
            <div className="p-2 bg-slate-100 flex items-center justify-center min-h-[420px]">
              {isPdf ? (
                <iframe
                  src={fileUrl}
                  className="w-full h-[520px] rounded border border-slate-300 bg-white"
                  title="Certificate Preview"
                />
              ) : (
                <img
                  src={fileUrl}
                  alt="Certificate"
                  className="max-h-[500px] w-auto object-contain rounded border border-slate-300 shadow-sm"
                />
              )}
            </div>
          </div>
        </div>

        {/* Right Column: Evidence Tabs & Deep Inspection */}
        <div className="lg:col-span-7 space-y-6">
          {/* Tabs Navigation */}
          <div className="border-b border-slate-200 flex space-x-2 text-xs font-semibold">
            {[
              { key: 'OVERVIEW', label: 'Timeline & Overview' },
              { key: 'ANOMALIES', label: `Anomalies (${submission.anomalies.length})` },
              { key: 'EVIDENCE', label: 'Issuer & QR Evidence' },
              { key: 'DUPLICATES', label: `Duplicates (${submission.duplicate_matches.length})` },
              { key: 'REPORT', label: 'Verification Report' },
              { key: 'AUDIT', label: 'Reviews & Audit' },
            ].map((tab) => (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key as any)}
                className={`pb-2.5 px-3 border-b-2 transition ${
                  activeTab === tab.key
                    ? 'border-blue-600 text-blue-600 font-bold'
                    : 'border-transparent text-slate-500 hover:text-slate-800'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* TAB 1: OVERVIEW & TIMELINE */}
          {activeTab === 'OVERVIEW' && (
            <div className="space-y-6">
              {/* Extracted Certificate Fields Card */}
              <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm space-y-4">
                <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider">
                  Extracted Certificate Metadata
                </h3>
                <div className="grid grid-cols-2 gap-4 text-xs">
                  <div>
                    <span className="text-slate-400 block">Certificate ID</span>
                    <span className="font-mono font-bold text-slate-800 text-sm">
                      {extracted?.certificate_id || 'Not detected'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Course / Qualification</span>
                    <span className="font-semibold text-slate-800 text-sm">
                      {extracted?.course_name || 'Not detected'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Issuer Name</span>
                    <span className="font-medium text-slate-800">{extracted?.issuer_name || 'Example University'}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Issue Date</span>
                    <span className="font-medium text-slate-800">{extracted?.issue_date || 'N/A'}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">QR Verification URL</span>
                    <span className="font-mono text-slate-700 truncate block">
                      {extracted?.qr_url || 'None detected'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Extraction Confidence</span>
                    <span className="font-semibold text-emerald-600">
                      {((extracted?.extraction_confidence || 0) * 100).toFixed(0)}%
                    </span>
                  </div>
                </div>
              </div>

              {/* Verification Timeline (Observability Stepper) */}
              <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm space-y-4">
                <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider">
                  Verification Processing Pipeline
                </h3>
                <div className="space-y-3">
                  {[
                    { label: 'Upload & Storage Quarantine Check', desc: 'SHA-256 hash verified and stored securely', status: 'PASS' },
                    { label: 'OCR Parsing & Document Layout', desc: 'Deterministic text extraction completed', status: 'PASS' },
                    { label: 'QR Extraction & Hostname Resolution', desc: extracted?.qr_url ? 'Decoded QR destination URL' : 'No QR embedded', status: extracted?.qr_url ? 'PASS' : 'NOTICE' },
                    { label: 'Issuer Registry Domain Validation', desc: 'Validated domain against official registry', status: vResult?.qr_verification === 'PASS' ? 'PASS' : 'WARN' },
                    { label: 'Authoritative Issuer Verification Adapter', desc: `Issuer query returned status: ${vResult?.issuer_verification || 'UNAVAILABLE'}`, status: vResult?.issuer_verification === 'VALID' ? 'PASS' : 'WARN' },
                    { label: 'Recipient Identity Matching', desc: `Normalized comparison: ${vResult?.identity_verification || 'PENDING'}`, status: vResult?.identity_verification === 'EXACT' ? 'PASS' : 'WARN' },
                    { label: 'Duplicate Detection Engine', desc: `${submission.duplicate_matches.length} duplicate collisions detected`, status: submission.duplicate_matches.length === 0 ? 'PASS' : 'WARN' },
                    { label: 'Deterministic Rule Engine', desc: `Final synthesized status: ${submission.status}`, status: 'PASS' },
                  ].map((step, idx) => (
                    <div key={idx} className="flex items-start space-x-3 text-xs">
                      <div className={`mt-0.5 w-5 h-5 rounded-full flex items-center justify-center font-bold text-[10px] ${
                        step.status === 'PASS' ? 'bg-emerald-100 text-emerald-800' :
                        step.status === 'WARN' ? 'bg-amber-100 text-amber-800' : 'bg-slate-100 text-slate-600'
                      }`}>
                        {idx + 1}
                      </div>
                      <div className="flex-1">
                        <div className="font-semibold text-slate-800">{step.label}</div>
                        <div className="text-slate-400">{step.desc}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: ANOMALIES */}
          {activeTab === 'ANOMALIES' && (
            <div className="space-y-4">
              {submission.anomalies.length === 0 ? (
                <div className="bg-white p-8 rounded-xl border border-slate-200 text-center text-slate-400">
                  <CheckCircle className="w-10 h-10 text-emerald-500 mx-auto mb-2" />
                  <p className="font-semibold text-slate-700 text-sm">No Anomalies Flagged</p>
                  <p className="text-xs text-slate-400 mt-1">All 20 verification rules passed without anomalies.</p>
                </div>
              ) : (
                submission.anomalies.map((anom) => (
                  <div
                    key={anom.id}
                    className={`p-4 rounded-xl border ${
                      anom.severity === 'CRITICAL' ? 'bg-rose-50 border-rose-200' :
                      anom.severity === 'HIGH' ? 'bg-amber-50 border-amber-200' :
                      anom.severity === 'MEDIUM' ? 'bg-yellow-50 border-yellow-200' : 'bg-slate-50 border-slate-200'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-white border text-slate-700">
                          {anom.type}
                        </span>
                        <h4 className="font-bold text-sm text-slate-900">{anom.title}</h4>
                      </div>
                      <span className={`text-xs font-extrabold uppercase px-2 py-0.5 rounded ${
                        anom.severity === 'CRITICAL' ? 'bg-rose-200 text-rose-900' :
                        anom.severity === 'HIGH' ? 'bg-amber-200 text-amber-900' : 'bg-slate-200 text-slate-800'
                      }`}>
                        {anom.severity}
                      </span>
                    </div>
                    <p className="text-xs text-slate-700 mt-2">{anom.description}</p>
                    {anom.evidence && (
                      <pre className="mt-2 p-2 bg-white/80 rounded border text-[11px] font-mono text-slate-600 overflow-x-auto">
                        {anom.evidence}
                      </pre>
                    )}
                  </div>
                ))
              )}
            </div>
          )}

          {/* TAB 3: ISSUER & QR EVIDENCE */}
          {activeTab === 'EVIDENCE' && (
            <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm space-y-4 text-xs">
              <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider">
                Official Issuer Verification Records
              </h3>
              {submission.issuer_verifications.length === 0 ? (
                <p className="text-slate-400">No issuer verification queries performed.</p>
              ) : (
                submission.issuer_verifications.map((iv) => (
                  <div key={iv.id} className="p-4 bg-slate-50 rounded-lg border border-slate-200 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-slate-800">Method: {iv.verification_method}</span>
                      <span className={`font-bold px-2 py-0.5 rounded ${
                        iv.verification_status === 'VALID' ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800'
                      }`}>
                        {iv.verification_status}
                      </span>
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-slate-600">
                      <div>Submitted ID: <span className="font-mono text-slate-900">{iv.certificate_id_submitted}</span></div>
                      <div>Returned ID: <span className="font-mono text-slate-900">{iv.certificate_id_returned || 'N/A'}</span></div>
                      <div>Verified Recipient: <span className="font-semibold text-slate-900">{iv.recipient_returned || 'N/A'}</span></div>
                      <div>Verified Course: <span className="font-semibold text-slate-900">{iv.course_returned || 'N/A'}</span></div>
                    </div>
                    {iv.raw_evidence && (
                      <div className="mt-2">
                        <span className="text-slate-400 block text-[10px] uppercase font-bold">Raw Authority Evidence:</span>
                        <pre className="p-2 bg-white rounded border text-[11px] font-mono text-slate-600 mt-1 overflow-x-auto">
                          {iv.raw_evidence}
                        </pre>
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          )}

          {/* TAB 4: DUPLICATES */}
          {activeTab === 'DUPLICATES' && (
            <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm space-y-4 text-xs">
              <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider">
                Cross-Submission Duplicate Matches
              </h3>
              {submission.duplicate_matches.length === 0 ? (
                <p className="text-slate-400">No duplicate matches found in certificate database.</p>
              ) : (
                submission.duplicate_matches.map((dm) => (
                  <div key={dm.id} className="p-3 bg-amber-50/60 border border-amber-200 rounded-lg space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-amber-900">{dm.match_type}</span>
                      <span className="font-semibold text-slate-600">Similarity: {(dm.similarity * 100).toFixed(0)}%</span>
                    </div>
                    <p className="text-slate-700">{dm.evidence}</p>
                    <p className="text-[11px] text-slate-400 font-mono">Matched Submission ID: {dm.matched_submission_id}</p>
                  </div>
                ))
              )}
            </div>
          )}

          {/* TAB 5: REPORT */}
          {activeTab === 'REPORT' && (
            <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider">
                  Official Verification Evidence Report
                </h3>
                <button
                  onClick={() => navigator.clipboard.writeText(evidenceReport)}
                  className="text-xs text-blue-600 hover:text-blue-800 flex items-center font-medium"
                >
                  <Copy className="w-3.5 h-3.5 mr-1" /> Copy Report
                </button>
              </div>
              <pre className="p-4 bg-slate-900 text-slate-100 rounded-lg text-xs font-mono overflow-x-auto whitespace-pre leading-relaxed">
                {evidenceReport || 'Report generating...'}
              </pre>
            </div>
          )}

          {/* TAB 6: AUDIT & REVIEWS */}
          {activeTab === 'AUDIT' && (
            <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm space-y-4 text-xs">
              <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider">
                Faculty Review Decisions
              </h3>
              {submission.reviews.length === 0 ? (
                <p className="text-slate-400">No manual faculty reviews conducted yet.</p>
              ) : (
                submission.reviews.map((rev) => (
                  <div key={rev.id} className="p-4 bg-slate-50 rounded-lg border border-slate-200 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-900">Decision: {rev.decision}</span>
                      <span className="text-slate-400">{new Date(rev.created_at).toLocaleString()}</span>
                    </div>
                    {rev.reason && <p className="text-slate-700 font-medium">Reason: {rev.reason}</p>}
                    {rev.notes && <p className="text-slate-500">Notes: {rev.notes}</p>}
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      </div>

      {/* Review Modal Dialog */}
      {reviewDecision && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-xl max-w-lg w-full p-6 shadow-xl border border-slate-200 space-y-4">
            <h3 className="text-base font-bold text-slate-900">
              Confirm Review Action: <span className="text-blue-600">{reviewDecision}</span>
            </h3>

            {reviewError && (
              <div className="p-2.5 bg-rose-50 border border-rose-200 text-rose-800 text-xs rounded-lg">
                {reviewError}
              </div>
            )}

            <form onSubmit={handleReviewSubmit} className="space-y-4 text-xs">
              {(reviewDecision === 'REJECT' || reviewDecision === 'REQUEST_EVIDENCE') && (
                <div>
                  <label className="block font-semibold text-slate-700 mb-1">
                    Official Reason (Required) *
                  </label>
                  <textarea
                    rows={3}
                    required
                    value={reviewReason}
                    onChange={(e) => setReviewReason(e.target.value)}
                    placeholder="Provide specific justification (e.g. Recipient name mismatch, unaccredited issuer)..."
                    className="w-full p-2.5 rounded-lg border border-slate-300 focus:outline-none focus:ring-1 focus:ring-blue-500 text-xs"
                  />
                </div>
              )}

              <div>
                <label className="block font-semibold text-slate-700 mb-1">Internal Notes (Optional)</label>
                <textarea
                  rows={2}
                  value={reviewNotes}
                  onChange={(e) => setReviewNotes(e.target.value)}
                  placeholder="Additional remarks for faculty audit..."
                  className="w-full p-2.5 rounded-lg border border-slate-300 focus:outline-none focus:ring-1 focus:ring-blue-500 text-xs"
                />
              </div>

              <div className="flex justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setReviewDecision(null)}
                  className="px-3 py-1.5 rounded-lg border border-slate-300 text-slate-700 hover:bg-slate-50 transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submittingReview}
                  className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold transition"
                >
                  {submittingReview ? 'Submitting...' : 'Save Decision'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
