'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { UploadCloud, FileText, CheckCircle2, AlertCircle, ShieldAlert, ArrowLeft } from 'lucide-react';
import Link from 'next/link';
import { api } from '@/lib/api';

export default function SubmitCertificatePage() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const router = useRouter();

  const handleFileChange = (file: File) => {
    setErrorMessage(null);
    const validExtensions = ['.pdf', '.png', '.jpg', '.jpeg'];
    const ext = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();

    if (!validExtensions.includes(ext)) {
      setErrorMessage(`Invalid file format '${ext}'. Only PDF, PNG, and JPG documents are accepted.`);
      return;
    }

    if (file.size > 15 * 1024 * 1024) {
      setErrorMessage(`File size ${(file.size / (1024 * 1024)).toFixed(1)}MB exceeds maximum allowed limit of 15MB.`);
      return;
    }

    setSelectedFile(file);
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileChange(e.dataTransfer.files[0]);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) return;

    try {
      setUploading(true);
      setErrorMessage(null);
      const res = await api.uploadCertificate(selectedFile);
      // Redirect to submission detail page to view verification progress
      router.push(`/submissions/${res.id}`);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to submit certificate');
      setUploading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <Link href="/" className="inline-flex items-center text-xs font-semibold text-slate-500 hover:text-slate-800 transition">
        <ArrowLeft className="w-3.5 h-3.5 mr-1" /> Back to Dashboard
      </Link>

      <div className="bg-white p-8 rounded-xl border border-slate-200 shadow-sm space-y-6">
        <div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight">Submit Certificate for Verification</h1>
          <p className="text-xs text-slate-500 mt-1">
            Uploaded credentials undergo cryptographic hashing, deterministic OCR, QR code analysis, issuer verification, and anomaly detection.
          </p>
        </div>

        {errorMessage && (
          <div className="p-3 bg-rose-50 border border-rose-200 rounded-lg flex items-start space-x-2 text-rose-800 text-xs">
            <AlertCircle className="w-4 h-4 text-rose-600 flex-shrink-0 mt-0.5" />
            <span>{errorMessage}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Dropzone */}
          <div
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            className={`border-2 border-dashed rounded-xl p-8 text-center transition-colors cursor-pointer ${
              dragActive ? 'border-blue-500 bg-blue-50/50' : 'border-slate-300 hover:border-slate-400 bg-slate-50/50'
            }`}
            onClick={() => document.getElementById('file-upload-input')?.click()}
          >
            <input
              id="file-upload-input"
              type="file"
              accept=".pdf,.png,.jpg,.jpeg"
              className="hidden"
              onChange={(e) => {
                if (e.target.files && e.target.files[0]) {
                  handleFileChange(e.target.files[0]);
                }
              }}
            />

            <UploadCloud className="w-10 h-10 mx-auto text-slate-400 mb-2" />
            <p className="text-sm font-semibold text-slate-700">Click to upload or drag & drop</p>
            <p className="text-xs text-slate-400 mt-1">PDF, PNG, JPG (Maximum file size: 15MB)</p>

            {selectedFile && (
              <div className="mt-4 inline-flex items-center space-x-2 bg-blue-100 text-blue-800 px-3 py-1.5 rounded-lg text-xs font-medium">
                <FileText className="w-4 h-4 text-blue-600" />
                <span>{selectedFile.name} ({(selectedFile.size / 1024).toFixed(0)} KB)</span>
              </div>
            )}
          </div>

          {/* Security Principle Note */}
          <div className="bg-slate-50 border border-slate-200 rounded-lg p-3 text-xs text-slate-600 space-y-1">
            <div className="flex items-center font-semibold text-slate-700">
              <ShieldAlert className="w-4 h-4 mr-1.5 text-blue-600" /> Security Notice
            </div>
            <p className="text-slate-500">
              Your file is cryptographically hashed with SHA-256 immediately upon arrival. Uploaded certificates are never blindly trusted; official issuer registries and faculty authority govern authenticity.
            </p>
          </div>

          <button
            type="submit"
            disabled={!selectedFile || uploading}
            className="w-full py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 disabled:bg-slate-300 text-white font-medium text-sm transition shadow-sm flex items-center justify-center space-x-2"
          >
            {uploading ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                <span>Uploading & Starting Verification Pipeline...</span>
              </>
            ) : (
              <span>Submit Certificate for Verification</span>
            )}
          </button>
        </form>
      </div>
    </div>
  );
}
