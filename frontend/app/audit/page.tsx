'use client';

import { useState, useEffect } from 'react';
import { History, ShieldCheck, UserCheck, Lock } from 'lucide-react';
import { api } from '@/lib/api';
import { AuditLog } from '@/types';

export default function AuditLogsPage() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadLogs();
  }, []);

  const loadLogs = async () => {
    try {
      setLoading(true);
      const data = await api.getAuditLogs();
      setLogs(data);
    } catch (err) {
      console.error('Failed to load audit logs:', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh]">
        <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
        <p className="mt-4 text-sm text-slate-500 font-medium">Loading Immutable Audit Logs...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight flex items-center">
            <Lock className="w-5 h-5 mr-2 text-blue-600" /> Immutable System Audit Trail
          </h1>
          <p className="text-xs text-slate-500 mt-1">
            Every critical action (upload, automated verification milestone, faculty override) is cryptographically recorded.
          </p>
        </div>
        <span className="text-xs bg-emerald-50 text-emerald-800 border border-emerald-200 font-semibold px-3 py-1 rounded-full flex items-center">
          <ShieldCheck className="w-3.5 h-3.5 mr-1 text-emerald-600" /> Tamper-Evident Ledger
        </span>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
        <table className="min-w-full divide-y divide-slate-200 text-left text-sm">
          <thead className="bg-slate-50 text-slate-500 text-xs uppercase font-medium">
            <tr>
              <th className="px-6 py-3">Timestamp</th>
              <th className="px-6 py-3">Actor</th>
              <th className="px-6 py-3">Action</th>
              <th className="px-6 py-3">Entity</th>
              <th className="px-6 py-3">Prior State</th>
              <th className="px-6 py-3">New State</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 text-xs font-mono">
            {logs.length === 0 && (
              <tr>
                <td colSpan={6} className="px-6 py-10 text-center text-slate-400 font-sans text-sm">
                  No audit events recorded yet — events appear here after certificate
                  uploads, verifications, reviews and batch analyses.
                </td>
              </tr>
            )}
            {logs.map((log) => (
              <tr key={log.id} className="hover:bg-slate-50">
                <td className="px-6 py-3.5 text-slate-500">
                  {new Date(log.created_at).toLocaleString()}
                </td>
                <td className="px-6 py-3.5 font-sans font-medium text-slate-900">
                  {log.actor_name || log.actor_user_id || 'System Worker'}
                </td>
                <td className="px-6 py-3.5">
                  <span className="px-2 py-0.5 rounded bg-blue-50 text-blue-800 font-semibold border border-blue-200">
                    {log.action}
                  </span>
                </td>
                <td className="px-6 py-3.5 text-slate-700">
                  {log.entity_type} ({log.entity_id.substring(0, 8)}...)
                </td>
                <td className="px-6 py-3.5 text-slate-500">
                  {log.old_value || 'None'}
                </td>
                <td className="px-6 py-3.5 text-slate-900 font-semibold">
                  {log.new_value || 'N/A'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
