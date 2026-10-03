'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import {
  AlertCircle,
  ArrowLeft,
  CheckCircle2,
  Download,
  FileSpreadsheet,
  Link2,
  Loader2,
  ShieldAlert,
  Table2,
  UploadCloud,
  XCircle,
} from 'lucide-react';
import { api } from '@/lib/api';
import { BatchAnalysis } from '@/types';

const INPUT_COLUMNS = [
  'RECIPIENT_NAME',
  'CERTIFICATE_ID',
  'COURSE',
  'ISSUER',
  'CERTIFICATE_URL',
  'ISSUE_DATE',
  'EXPIRY_DATE',
];

const OUTPUT_COLUMNS = [
  'VERDICT',
  'MAX_SEVERITY',
  'ANOMALY_CODES',
  'ANALYSIS',
  'CONFIDENCE',
];

function verdictBadge(verdict: 'LEGIT' | 'FAKE' | 'ANOMALY', count: number) {
  const styles = {
    LEGIT: 'bg-emerald-100 text-emerald-800 border-emerald-200',
    FAKE: 'bg-rose-100 text-rose-800 border-rose-200',
    ANOMALY: 'bg-amber-100 text-amber-800 border-amber-200',
  };
  return (
    <span
      className={`inline-flex items-center px-2.5 py-1 rounded-md border text-xs font-bold ${styles[verdict]}`}
    >
      {verdict}: {count}
    </span>
  );
}

export default function BatchAnalysisPage() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [activeBatch, setActiveBatch] = useState<BatchAnalysis | null>(null);
  const [batches, setBatches] = useState<BatchAnalysis[]>([]);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [sheetUrl, setSheetUrl] = useState('');
  const [importing, setImporting] = useState(false);

  const loadBatches = useCallback(async () => {
    try {
      setBatches(await api.getBatches());
    } catch {
      // list is non-critical; keep last known state
    }
  }, []);

  useEffect(() => {
    loadBatches();
  }, [loadBatches]);

  // Poll while any batch is still processing
  useEffect(() => {
    const processing =
      (activeBatch && activeBatch.status === 'PROCESSING') ||
      batches.some((b) => b.status === 'PROCESSING');
    if (!processing) return;
    const timer = setInterval(async () => {
      try {
        if (activeBatch && activeBatch.status === 'PROCESSING') {
          const refreshed = await api.getBatch(activeBatch.id);
          setActiveBatch(refreshed);
        }
        await loadBatches();
      } catch {
        // transient polling error
      }
    }, 2000);
    return () => clearInterval(timer);
  }, [activeBatch, batches, loadBatches]);

  const handleFileChange = (file: File) => {
    setErrorMessage(null);
    const ext = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
    if (ext !== '.xlsx') {
      setErrorMessage(
        `Invalid file format '${ext}'. Only .xlsx workbooks are accepted - download the official template first.`
      );
      return;
    }
    if (file.size > 15 * 1024 * 1024) {
      setErrorMessage(
        `File size ${(file.size / (1024 * 1024)).toFixed(1)}MB exceeds maximum allowed limit of 15MB.`
      );
      return;
    }
    setSelectedFile(file);
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') setDragActive(true);
    if (e.type === 'dragleave' || e.type === 'dragleave') setDragActive(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files?.[0]) handleFileChange(e.dataTransfer.files[0]);
  };

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) return;
    try {
      setUploading(true);
      setErrorMessage(null);
      const batch = await api.uploadBatch(selectedFile);
      setActiveBatch(batch);
      setSelectedFile(null);
      await loadBatches();
      // Ensure deterministic progress even if the background worker is queued
      const finished = await api.processBatch(batch.id);
      setActiveBatch(finished);
      await loadBatches();
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to upload workbook');
    } finally {
      setUploading(false);
    }
  };

  const handleGoogleSheet = async (e: React.FormEvent) => {
    e.preventDefault();
    const url = sheetUrl.trim();
    if (!url) return;
    try {
      setImporting(true);
      setErrorMessage(null);
      const batch = await api.uploadBatchFromGoogleSheet(url);
      setActiveBatch(batch);
      setSheetUrl('');
      await loadBatches();
      const finished = await api.processBatch(batch.id);
      setActiveBatch(finished);
      await loadBatches();
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to import Google Sheet');
    } finally {
      setImporting(false);
    }
  };

  const handleDownload = async (batch: BatchAnalysis) => {
    try {
      setDownloadingId(batch.id);
      await api.downloadBatchResult(batch);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to download result');
    } finally {
      setDownloadingId(null);
    }
  };

  const counts = activeBatch?.verdict_counts;

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <Link
        href="/"
        className="inline-flex items-center text-xs font-semibold text-slate-500 hover:text-slate-800 transition"
      >
        <ArrowLeft className="w-3.5 h-3.5 mr-1" /> Back to Dashboard
      </Link>

      <div className="bg-white p-8 rounded-xl border border-slate-200 shadow-sm space-y-6">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <h1 className="text-xl font-bold text-slate-900 tracking-tight">
              Batch Workbook Analysis
            </h1>
            <p className="text-xs text-slate-500 mt-1 max-w-2xl">
              Upload an Excel sheet where each row is one certificate. Every row is run
              through the same issuer-registry, identity and anomaly pipeline, and the
              platform writes LEGIT / FAKE / ANOMALY verdicts back into locked
              analysis columns.
            </p>
          </div>
          <button
            type="button"
            onClick={() => api.downloadBatchTemplate().catch((e) => setErrorMessage(e.message))}
            className="inline-flex items-center px-3.5 py-2 rounded-lg border border-blue-200 bg-blue-50 text-blue-700 hover:bg-blue-100 text-xs font-semibold transition"
          >
            <Download className="w-4 h-4 mr-1.5" /> Download Official Template
          </button>
        </div>

        {errorMessage && (
          <div className="p-3 bg-rose-50 border border-rose-200 rounded-lg flex items-start space-x-2 text-rose-800 text-xs">
            <AlertCircle className="w-4 h-4 text-rose-600 flex-shrink-0 mt-0.5" />
            <span className="break-words">{errorMessage}</span>
          </div>
        )}

        {/* Format contract */}
        <div className="grid md:grid-cols-2 gap-4">
          <div className="border border-blue-200 rounded-lg p-4 bg-blue-50/40">
            <div className="text-xs font-bold text-blue-900 uppercase tracking-wide mb-2 flex items-center">
              <Table2 className="w-4 h-4 mr-1.5" /> Input zone (you edit)
            </div>
            <ul className="text-xs text-slate-600 space-y-1 font-mono">
              {INPUT_COLUMNS.map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ul>
          </div>
          <div className="border border-slate-300 rounded-lg p-4 bg-slate-100/60">
            <div className="text-xs font-bold text-slate-700 uppercase tracking-wide mb-2 flex items-center">
              <ShieldAlert className="w-4 h-4 mr-1.5" /> Output &amp; analysis zone (locked)
            </div>
            <ul className="text-xs text-slate-600 space-y-1 font-mono">
              {OUTPUT_COLUMNS.map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ul>
            <p className="text-[11px] text-slate-500 mt-2">
              Pre-filled values in these columns are rejected on upload.
            </p>
          </div>
        </div>

        <form onSubmit={handleUpload} className="space-y-6">
          <div
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            className={`border-2 border-dashed rounded-xl p-8 text-center transition-colors cursor-pointer ${
              dragActive
                ? 'border-blue-500 bg-blue-50/50'
                : 'border-slate-300 hover:border-slate-400 bg-slate-50/50'
            }`}
            onClick={() => document.getElementById('batch-upload-input')?.click()}
          >
            <input
              id="batch-upload-input"
              type="file"
              accept=".xlsx"
              className="hidden"
              onChange={(e) => {
                if (e.target.files?.[0]) handleFileChange(e.target.files[0]);
              }}
            />
            <UploadCloud className="w-10 h-10 mx-auto text-slate-400 mb-2" />
            <p className="text-sm font-semibold text-slate-700">
              Click to upload or drag &amp; drop your workbook
            </p>
            <p className="text-xs text-slate-400 mt-1">
              .xlsx only, strict template format, maximum 500 rows
            </p>
            {selectedFile && (
              <div className="mt-4 inline-flex items-center space-x-2 bg-blue-100 text-blue-800 px-3 py-1.5 rounded-lg text-xs font-medium">
                <FileSpreadsheet className="w-4 h-4 text-blue-600" />
                <span>
                  {selectedFile.name} ({(selectedFile.size / 1024).toFixed(0)} KB)
                </span>
              </div>
            )}
          </div>

          <button
            type="submit"
            disabled={!selectedFile || uploading}
            className="w-full py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 disabled:bg-slate-300 text-white font-medium text-sm transition shadow-sm flex items-center justify-center space-x-2"
          >
            {uploading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Uploading &amp; analysing rows...</span>
              </>
            ) : (
              <span>Analyse Workbook</span>
            )}
          </button>
        </form>

        {/* Google Sheets intake */}
        <div className="border-t border-slate-200 pt-6">
          <div className="text-xs font-bold text-slate-700 uppercase tracking-wide mb-1 flex items-center">
            <Link2 className="w-4 h-4 mr-1.5 text-blue-600" /> Or analyse
            straight from a Google Sheet
          </div>
          <p className="text-xs text-slate-500 mb-3">
            Paste a docs.google.com spreadsheet link (set sharing to
            &quot;Anyone with the link can view&quot;). Columns like name,
            registration number and certificate links are detected
            automatically; analysis columns are always generated by the
            platform.
          </p>
          <form onSubmit={handleGoogleSheet} className="flex flex-col sm:flex-row gap-2">
            <input
              type="url"
              value={sheetUrl}
              onChange={(e) => {
                setSheetUrl(e.target.value);
                setErrorMessage(null);
              }}
              placeholder="https://docs.google.com/spreadsheets/d/..."
              className="flex-1 px-3 py-2.5 rounded-lg border border-slate-300 bg-white text-xs text-slate-800 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              required
            />
            <button
              type="submit"
              disabled={!sheetUrl.trim() || importing}
              className="inline-flex items-center justify-center px-4 py-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 disabled:bg-slate-300 text-white text-xs font-semibold transition"
            >
              {importing ? (
                <>
                  <Loader2 className="w-4 h-4 mr-1.5 animate-spin" />
                  Importing &amp; analysing...
                </>
              ) : (
                <>
                  <Link2 className="w-4 h-4 mr-1.5" />
                  Import Sheet
                </>
              )}
            </button>
          </form>
        </div>

        {/* Active batch result */}
        {activeBatch && (
          <div className="border border-slate-200 rounded-lg p-5 bg-slate-50/60 space-y-4">
            <div className="flex items-center justify-between flex-wrap gap-3">
              <div className="flex items-center space-x-2 text-sm font-semibold text-slate-800">
                {activeBatch.status === 'PROCESSING' && (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin text-blue-600" />
                    <span>
                      Analysing {activeBatch.processed_rows}/{activeBatch.total_rows} rows...
                    </span>
                  </>
                )}
                {activeBatch.status === 'COMPLETED' && (
                  <>
                    <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                    <span>
                      Analysis complete — {activeBatch.processed_rows} rows
                    </span>
                  </>
                )}
                {activeBatch.status === 'FAILED' && (
                  <>
                    <XCircle className="w-4 h-4 text-rose-600" />
                    <span>Analysis failed</span>
                  </>
                )}
              </div>
              {activeBatch.status === 'COMPLETED' && activeBatch.result_ready && (
                <button
                  type="button"
                  onClick={() => handleDownload(activeBatch)}
                  disabled={downloadingId === activeBatch.id}
                  className="inline-flex items-center px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-700 disabled:bg-slate-400 text-white text-xs font-semibold transition"
                >
                  {downloadingId === activeBatch.id ? (
                    <Loader2 className="w-4 h-4 mr-1.5 animate-spin" />
                  ) : (
                    <Download className="w-4 h-4 mr-1.5" />
                  )}
                  Download Analysed Workbook
                </button>
              )}
            </div>

            {counts && (
              <div className="flex flex-wrap gap-2">
                {verdictBadge('LEGIT', counts.LEGIT ?? 0)}
                {verdictBadge('FAKE', counts.FAKE ?? 0)}
                {verdictBadge('ANOMALY', counts.ANOMALY ?? 0)}
              </div>
            )}

            {activeBatch.error_message && (
              <div className="p-3 bg-rose-50 border border-rose-200 rounded-lg text-rose-800 text-xs">
                {activeBatch.error_message}
              </div>
            )}
          </div>
        )}
      </div>

      {/* History */}
      <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
        <h2 className="text-sm font-bold text-slate-800 mb-4">Batch History</h2>
        {batches.length === 0 ? (
          <p className="text-xs text-slate-400">No batch uploads yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-slate-400 border-b border-slate-200">
                  <th className="py-2 pr-4 font-medium">Workbook</th>
                  <th className="py-2 pr-4 font-medium">Status</th>
                  <th className="py-2 pr-4 font-medium">Rows</th>
                  <th className="py-2 pr-4 font-medium">Verdicts</th>
                  <th className="py-2 font-medium">Result</th>
                </tr>
              </thead>
              <tbody>
                {batches.map((b) => (
                  <tr key={b.id} className="border-b border-slate-100 last:border-0">
                    <td className="py-2.5 pr-4 font-medium text-slate-700 max-w-[180px] truncate">
                      {b.original_filename}
                    </td>
                    <td className="py-2.5 pr-4">
                      <span
                        className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                          b.status === 'COMPLETED'
                            ? 'bg-emerald-100 text-emerald-700'
                            : b.status === 'FAILED'
                            ? 'bg-rose-100 text-rose-700'
                            : 'bg-blue-100 text-blue-700'
                        }`}
                      >
                        {b.status}
                      </span>
                    </td>
                    <td className="py-2.5 pr-4 text-slate-600">
                      {b.processed_rows}/{b.total_rows}
                    </td>
                    <td className="py-2.5 pr-4">
                      <div className="flex gap-1.5 flex-wrap">
                        {b.verdict_counts ? (
                          <>
                            <span className="text-emerald-700 font-semibold">
                              L:{b.verdict_counts.LEGIT ?? 0}
                            </span>
                            <span className="text-rose-700 font-semibold">
                              F:{b.verdict_counts.FAKE ?? 0}
                            </span>
                            <span className="text-amber-700 font-semibold">
                              A:{b.verdict_counts.ANOMALY ?? 0}
                            </span>
                          </>
                        ) : (
                          <span className="text-slate-400">—</span>
                        )}
                      </div>
                    </td>
                    <td className="py-2.5">
                      {b.result_ready ? (
                        <button
                          type="button"
                          onClick={() => handleDownload(b)}
                          disabled={downloadingId === b.id}
                          className="inline-flex items-center text-blue-600 hover:text-blue-800 font-semibold disabled:text-slate-400"
                        >
                          {downloadingId === b.id ? (
                            <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          ) : (
                            <Download className="w-3.5 h-3.5 mr-1" />
                          )}
                          Download
                        </button>
                      ) : (
                        <span className="text-slate-400">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
