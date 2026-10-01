'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { 
  FileCheck2, 
  AlertTriangle, 
  XCircle, 
  HelpCircle, 
  Clock, 
  ShieldCheck, 
  Upload, 
  ArrowUpRight, 
  Search,
  Filter,
  Users,
  Award
} from 'lucide-react';
import { api } from '@/lib/api';
import { Submission, PlatformStats, User } from '@/types';

export default function DashboardPage() {
  const [submissions, setSubmissions] = useState<Submission[]>([]);
  const [stats, setStats] = useState<PlatformStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [currentUser, setCurrentUser] = useState<User | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const user = api.getCurrentUser();
      setCurrentUser(user);
      const [subs, st] = await Promise.all([
        api.getSubmissions(),
        api.getStats().catch(() => null),
      ]);
      setSubmissions(subs);
      setStats(st);
    } catch (err) {
      console.error('Failed to load dashboard:', err);
    } finally {
      setLoading(false);
    }
  };

  const isStudent = currentUser?.role === 'STUDENT';

  const filteredSubmissions = submissions.filter((sub) => {
    if (statusFilter !== 'ALL' && sub.status !== statusFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const studentName = sub.student?.full_name?.toLowerCase() || '';
      const certId = sub.extracted_data?.certificate_id?.toLowerCase() || '';
      const filename = sub.original_filename?.toLowerCase() || '';
      const course = sub.extracted_data?.course_name?.toLowerCase() || '';
      return studentName.includes(q) || certId.includes(q) || filename.includes(q) || course.includes(q);
    }
    return true;
  });

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'VERIFIED':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800 border border-emerald-300">
            <FileCheck2 className="w-3.5 h-3.5 mr-1 text-emerald-600" /> Verified
          </span>
        );
      case 'REVIEW':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-100 text-amber-900 border border-amber-300 animate-pulse">
            <AlertTriangle className="w-3.5 h-3.5 mr-1 text-amber-600" /> Review Required
          </span>
        );
      case 'FAILED':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-100 text-rose-800 border border-rose-300">
            <XCircle className="w-3.5 h-3.5 mr-1 text-rose-600" /> Failed
          </span>
        );
      case 'UNVERIFIABLE':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-100 text-slate-800 border border-slate-300">
            <HelpCircle className="w-3.5 h-3.5 mr-1 text-slate-600" /> Unverifiable
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-100 text-blue-800 border border-blue-300">
            <Clock className="w-3.5 h-3.5 mr-1 text-blue-600 animate-spin" /> Processing
          </span>
        );
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh]">
        <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
        <p className="mt-4 text-sm text-slate-500 font-medium">Loading CertificateGuard platform...</p>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between bg-white p-6 rounded-xl border border-slate-200 shadow-sm gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
            {isStudent ? 'Student Certificate Portal' : 'Faculty Verification Dashboard'}
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            {isStudent
              ? 'Upload your academic credentials and track verification progress in real-time.'
              : 'Audit automated evidence, inspect cryptographic signals, and perform teacher reviews.'}
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <Link
            href="/submit"
            className="inline-flex items-center justify-center px-4 py-2.5 rounded-lg bg-blue-600 text-white font-medium text-sm hover:bg-blue-700 transition shadow-sm"
          >
            <Upload className="w-4 h-4 mr-2" /> Submit Certificate
          </Link>
        </div>
      </div>

      {/* Metrics Cards (for Teachers / Admins) */}
      {!isStudent && stats && (
        <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
            <span className="text-xs font-medium text-slate-500 uppercase tracking-wider">Total Submissions</span>
            <div className="text-2xl font-bold text-slate-900 mt-1">{stats.total_submissions}</div>
          </div>
          <div className="bg-white p-4 rounded-xl border border-blue-200 shadow-sm bg-blue-50/30">
            <span className="text-xs font-medium text-blue-700 uppercase tracking-wider">Processing</span>
            <div className="text-2xl font-bold text-blue-600 mt-1">{stats.processing}</div>
          </div>
          <div className="bg-white p-4 rounded-xl border border-emerald-200 shadow-sm bg-emerald-50/30">
            <span className="text-xs font-medium text-emerald-700 uppercase tracking-wider">Verified</span>
            <div className="text-2xl font-bold text-emerald-600 mt-1">{stats.verified}</div>
          </div>
          <div className="bg-white p-4 rounded-xl border border-amber-200 shadow-sm bg-amber-50/40 ring-1 ring-amber-400">
            <span className="text-xs font-medium text-amber-800 uppercase tracking-wider">Needs Review</span>
            <div className="text-2xl font-bold text-amber-600 mt-1">{stats.needs_review}</div>
          </div>
          <div className="bg-white p-4 rounded-xl border border-rose-200 shadow-sm bg-rose-50/30">
            <span className="text-xs font-medium text-rose-700 uppercase tracking-wider">Failed</span>
            <div className="text-2xl font-bold text-rose-600 mt-1">{stats.failed}</div>
          </div>
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm bg-slate-50">
            <span className="text-xs font-medium text-slate-600 uppercase tracking-wider">Unverifiable</span>
            <div className="text-2xl font-bold text-slate-700 mt-1">{stats.unverifiable}</div>
          </div>
        </div>
      )}

      {/* Review Queue / Submissions Table */}
      <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
        {/* Filter Toolbar */}
        <div className="p-4 border-b border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center space-x-2">
            <h2 className="font-semibold text-base text-slate-800">
              {isStudent ? 'My Certificate Submissions' : 'Verification Queue'}
            </h2>
            <span className="text-xs px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 font-medium">
              {filteredSubmissions.length}
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {/* Search Box */}
            <div className="relative">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search student, cert ID, course..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9 pr-3 py-1.5 text-xs rounded-lg border border-slate-300 focus:outline-none focus:ring-1 focus:ring-blue-500 w-64"
              />
            </div>

            {/* Status Filter */}
            <div className="flex items-center space-x-1 bg-slate-100 p-1 rounded-lg text-xs">
              {['ALL', 'REVIEW', 'VERIFIED', 'FAILED', 'UNVERIFIABLE'].map((st) => (
                <button
                  key={st}
                  onClick={() => setStatusFilter(st)}
                  className={`px-2.5 py-1 rounded-md font-medium transition ${
                    statusFilter === st ? 'bg-white text-blue-600 shadow-sm' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {st === 'ALL' ? 'All' : st === 'REVIEW' ? 'Review' : st}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Table Content */}
        <div className="overflow-x-auto">
          {filteredSubmissions.length === 0 ? (
            <div className="p-12 text-center text-slate-400">
              <ShieldCheck className="w-12 h-12 mx-auto text-slate-300 mb-3" />
              <p className="font-medium text-slate-600 text-sm">No certificate submissions found</p>
              <p className="text-xs text-slate-400 mt-1">
                {isStudent
                  ? 'Submit your first certificate to initiate evidence-based verification.'
                  : 'Adjust your search filters or check back later.'}
              </p>
            </div>
          ) : (
            <table className="min-w-full divide-y divide-slate-200 text-left text-sm">
              <thead className="bg-slate-50 text-slate-500 text-xs uppercase font-medium">
                <tr>
                  <th className="px-6 py-3">Student</th>
                  <th className="px-6 py-3">Certificate / Course</th>
                  <th className="px-6 py-3">Certificate ID</th>
                  <th className="px-6 py-3">Status</th>
                  <th className="px-6 py-3">Anomalies</th>
                  <th className="px-6 py-3">Uploaded</th>
                  <th className="px-6 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredSubmissions.map((sub) => {
                  const criticalCount = sub.anomalies.filter((a) => a.severity === 'CRITICAL').length;
                  const highCount = sub.anomalies.filter((a) => a.severity === 'HIGH').length;

                  return (
                    <tr key={sub.id} className="hover:bg-slate-50/80 transition-colors">
                      <td className="px-6 py-4">
                        <div className="font-medium text-slate-900">{sub.student?.full_name || 'Student'}</div>
                        <div className="text-xs text-slate-400">{sub.student?.student_identifier || sub.student?.email}</div>
                      </td>
                      <td className="px-6 py-4">
                        <div className="font-medium text-slate-800">
                          {sub.extracted_data?.course_name || sub.original_filename}
                        </div>
                        <div className="text-xs text-slate-500">
                          {sub.extracted_data?.issuer_name || 'Example University'}
                        </div>
                      </td>
                      <td className="px-6 py-4 font-mono text-xs text-slate-700">
                        {sub.extracted_data?.certificate_id || 'Not detected'}
                      </td>
                      <td className="px-6 py-4">{getStatusBadge(sub.status)}</td>
                      <td className="px-6 py-4">
                        {sub.anomalies.length === 0 ? (
                          <span className="text-xs text-emerald-600 font-medium">Clean (0)</span>
                        ) : (
                          <div className="flex items-center space-x-1.5">
                            {criticalCount > 0 && (
                              <span className="px-1.5 py-0.5 rounded bg-rose-100 text-rose-800 text-xs font-semibold">
                                {criticalCount} Critical
                              </span>
                            )}
                            {highCount > 0 && (
                              <span className="px-1.5 py-0.5 rounded bg-amber-100 text-amber-800 text-xs font-semibold">
                                {highCount} High
                              </span>
                            )}
                            {criticalCount === 0 && highCount === 0 && (
                              <span className="text-xs text-slate-500 font-medium">
                                {sub.anomalies.length} Notice(s)
                              </span>
                            )}
                          </div>
                        )}
                      </td>
                      <td className="px-6 py-4 text-xs text-slate-500">
                        {new Date(sub.uploaded_at).toLocaleDateString()}
                      </td>
                      <td className="px-6 py-4 text-right">
                        <Link
                          href={`/submissions/${sub.id}`}
                          className="inline-flex items-center text-xs font-semibold text-blue-600 hover:text-blue-800 bg-blue-50 hover:bg-blue-100 px-3 py-1.5 rounded-md transition"
                        >
                          View Evidence <ArrowUpRight className="w-3.5 h-3.5 ml-1" />
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
