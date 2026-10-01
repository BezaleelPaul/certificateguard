'use client';

import { useState, useEffect } from 'react';
import { Building2, Plus, ShieldCheck, Globe, CheckCircle2, XCircle } from 'lucide-react';
import { api } from '@/lib/api';
import { Issuer } from '@/types';

export default function IssuersPage() {
  const [issuers, setIssuers] = useState<Issuer[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);

  // New issuer form state
  const [name, setName] = useState('');
  const [officialDomain, setOfficialDomain] = useState('');
  const [verificationType, setVerificationType] = useState('WEB');
  const [verificationUrl, setVerificationUrl] = useState('');
  const [configJson, setConfigJson] = useState('{}');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    loadIssuers();
  }, []);

  const loadIssuers = async () => {
    try {
      setLoading(true);
      const data = await api.getIssuers();
      setIssuers(data);
    } catch (err) {
      console.error('Failed to load issuers:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateIssuer = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setSubmitting(true);
      await api.createIssuer({
        name,
        official_domain: officialDomain,
        verification_type: verificationType,
        verification_url: verificationUrl || undefined,
        configuration_json: configJson || undefined,
        active: true,
      });
      setShowAddModal(false);
      setName('');
      setOfficialDomain('');
      setVerificationUrl('');
      await loadIssuers();
    } catch (err: any) {
      alert(err.message || 'Failed to create issuer');
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh]">
        <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
        <p className="mt-4 text-sm text-slate-500 font-medium">Loading Issuer Registry...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
        <div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight">Approved Issuer Registry</h1>
          <p className="text-xs text-slate-500 mt-1">
            Registered educational institutions and credential platforms approved for verification.
          </p>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="inline-flex items-center px-3.5 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-medium text-xs shadow-sm transition"
        >
          <Plus className="w-4 h-4 mr-1.5" /> Add New Issuer
        </button>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
        <table className="min-w-full divide-y divide-slate-200 text-left text-sm">
          <thead className="bg-slate-50 text-slate-500 text-xs uppercase font-medium">
            <tr>
              <th className="px-6 py-3">Institution / Issuer</th>
              <th className="px-6 py-3">Official Domain</th>
              <th className="px-6 py-3">Verification Mechanism</th>
              <th className="px-6 py-3">Portal URL</th>
              <th className="px-6 py-3">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 text-xs">
            {issuers.map((iss) => (
              <tr key={iss.id} className="hover:bg-slate-50">
                <td className="px-6 py-4 font-semibold text-slate-900 flex items-center">
                  <Building2 className="w-4 h-4 mr-2 text-blue-600" />
                  {iss.name}
                </td>
                <td className="px-6 py-4 font-mono text-slate-700">{iss.official_domain}</td>
                <td className="px-6 py-4 font-semibold text-slate-700">
                  <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-800 border">
                    {iss.verification_type}
                  </span>
                </td>
                <td className="px-6 py-4 text-slate-500 font-mono truncate max-w-xs">
                  {iss.verification_url || 'N/A'}
                </td>
                <td className="px-6 py-4">
                  {iss.active ? (
                    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800">
                      <CheckCircle2 className="w-3 h-3 mr-1 text-emerald-600" /> Active
                    </span>
                  ) : (
                    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-slate-100 text-slate-600">
                      <XCircle className="w-3 h-3 mr-1 text-slate-500" /> Inactive
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Add Issuer Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-xl max-w-md w-full p-6 shadow-xl border border-slate-200 space-y-4">
            <h3 className="text-base font-bold text-slate-900">Add Approved Issuer</h3>
            <form onSubmit={handleCreateIssuer} className="space-y-3 text-xs">
              <div>
                <label className="block font-semibold text-slate-700 mb-1">Issuer Name *</label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Stanford University"
                  className="w-full p-2 border rounded-lg"
                />
              </div>
              <div>
                <label className="block font-semibold text-slate-700 mb-1">Official Domain (strict) *</label>
                <input
                  type="text"
                  required
                  value={officialDomain}
                  onChange={(e) => setOfficialDomain(e.target.value)}
                  placeholder="e.g. stanford.edu"
                  className="w-full p-2 border rounded-lg font-mono"
                />
              </div>
              <div>
                <label className="block font-semibold text-slate-700 mb-1">Verification Type</label>
                <select
                  value={verificationType}
                  onChange={(e) => setVerificationType(e.target.value)}
                  className="w-full p-2 border rounded-lg"
                >
                  <option value="WEB">WEB (Playwright / Portal)</option>
                  <option value="API">API (REST / Cryptographic)</option>
                  <option value="MANUAL">MANUAL Review</option>
                </select>
              </div>
              <div>
                <label className="block font-semibold text-slate-700 mb-1">Verification Portal URL</label>
                <input
                  type="url"
                  value={verificationUrl}
                  onChange={(e) => setVerificationUrl(e.target.value)}
                  placeholder="https://stanford.edu/verify"
                  className="w-full p-2 border rounded-lg font-mono"
                />
              </div>
              <div>
                <label className="block font-semibold text-slate-700 mb-1">Configuration JSON (Selectors / Headers)</label>
                <textarea
                  rows={2}
                  value={configJson}
                  onChange={(e) => setConfigJson(e.target.value)}
                  className="w-full p-2 border rounded-lg font-mono"
                />
              </div>
              <div className="flex justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3 py-1.5 rounded-lg border text-slate-700 hover:bg-slate-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-4 py-1.5 rounded-lg bg-blue-600 text-white font-semibold hover:bg-blue-700"
                >
                  {submitting ? 'Saving...' : 'Add Issuer'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
