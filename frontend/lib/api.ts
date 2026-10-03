import { User, Submission, Issuer, AuditLog, PlatformStats, TeacherDecision, UserRole, BatchAnalysis } from '@/types';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

class ApiService {
  private getAuthHeaders(): HeadersInit {
    if (typeof window === 'undefined') return {};
    const token = localStorage.getItem('token');
    return token ? { Authorization: `Bearer ${token}` } : {};
  }

  async login(role: UserRole = 'TEACHER'): Promise<{ token: string; user: User }> {
    const res = await fetch(`${API_BASE}/api/auth/switch-role`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_role: role }),
    });
    if (!res.ok) throw new Error('Login failed');
    const data = await res.json();
    if (typeof window !== 'undefined') {
      localStorage.setItem('token', data.access_token);
      localStorage.setItem('user', JSON.stringify(data.user));
    }
    return { token: data.access_token, user: data.user };
  }

  getCurrentUser(): User | null {
    if (typeof window === 'undefined') return null;
    const userStr = localStorage.getItem('user');
    return userStr ? JSON.parse(userStr) : null;
  }

  async validateSession(): Promise<User | null> {
    if (!localStorage.getItem('token')) return null;
    const res = await fetch(`${API_BASE}/api/auth/me`, {
      headers: this.getAuthHeaders(),
    });
    if (!res.ok) return null;
    const user = await res.json();
    if (typeof window !== 'undefined') {
      localStorage.setItem('user', JSON.stringify(user));
    }
    return user;
  }

  async getSubmissions(): Promise<Submission[]> {
    const res = await fetch(`${API_BASE}/api/submissions`, {
      headers: this.getAuthHeaders(),
    });
    if (!res.ok) throw new Error('Failed to fetch submissions');
    return res.json();
  }

  async getSubmission(id: string): Promise<Submission> {
    const res = await fetch(`${API_BASE}/api/submissions/${id}`, {
      headers: this.getAuthHeaders(),
    });
    if (!res.ok) throw new Error('Failed to fetch submission');
    return res.json();
  }

  async uploadCertificate(file: File): Promise<any> {
    const formData = new FormData();
    formData.append('file', file);

    const res = await fetch(`${API_BASE}/api/submissions`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Upload failed' }));
      throw new Error(err.detail || 'Upload failed');
    }
    return res.json();
  }

  async processSubmission(id: string): Promise<Submission> {
    const res = await fetch(`${API_BASE}/api/submissions/${id}/process`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
    });
    if (!res.ok) throw new Error('Failed to process verification');
    return res.json();
  }

  async submitReview(id: string, decision: TeacherDecision, reason?: string, notes?: string): Promise<any> {
    const res = await fetch(`${API_BASE}/api/submissions/${id}/review`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...this.getAuthHeaders(),
      },
      body: JSON.stringify({ decision, reason, notes }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Review failed' }));
      throw new Error(err.detail || 'Review submission failed');
    }
    return res.json();
  }

  async getEvidenceReport(id: string): Promise<string> {
    const res = await fetch(`${API_BASE}/api/submissions/${id}/evidence`, {
      headers: this.getAuthHeaders(),
    });
    if (!res.ok) throw new Error('Failed to load evidence report');
    return res.text();
  }

  async getIssuers(): Promise<Issuer[]> {
    const res = await fetch(`${API_BASE}/api/issuers`, {
      headers: this.getAuthHeaders(),
    });
    if (!res.ok) throw new Error('Failed to fetch issuers');
    return res.json();
  }

  async createIssuer(issuerData: Partial<Issuer>): Promise<Issuer> {
    const res = await fetch(`${API_BASE}/api/issuers`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...this.getAuthHeaders(),
      },
      body: JSON.stringify(issuerData),
    });
    if (!res.ok) throw new Error('Failed to create issuer');
    return res.json();
  }

  async getAuditLogs(): Promise<AuditLog[]> {
    const res = await fetch(`${API_BASE}/api/audit-logs`, {
      headers: this.getAuthHeaders(),
    });
    if (!res.ok) throw new Error('Failed to fetch audit logs');
    return res.json();
  }

  async getStats(): Promise<PlatformStats> {
    const res = await fetch(`${API_BASE}/api/stats`, {
      headers: this.getAuthHeaders(),
    });
    if (!res.ok) throw new Error('Failed to fetch statistics');
    return res.json();
  }

  getFileUrl(submissionId: string): string {
    return `${API_BASE}/api/submissions/${submissionId}/file`;
  }

  async getBatches(): Promise<BatchAnalysis[]> {
    const res = await fetch(`${API_BASE}/api/batch`, {
      headers: this.getAuthHeaders(),
    });
    if (!res.ok) throw new Error('Failed to fetch batch analyses');
    return res.json();
  }

  async getBatch(id: string): Promise<BatchAnalysis> {
    const res = await fetch(`${API_BASE}/api/batch/${id}`, {
      headers: this.getAuthHeaders(),
    });
    if (!res.ok) throw new Error('Failed to fetch batch analysis');
    return res.json();
  }

  async uploadBatch(file: File): Promise<BatchAnalysis> {
    const formData = new FormData();
    formData.append('file', file);

    const res = await fetch(`${API_BASE}/api/batch`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Upload failed' }));
      const detail = err.detail;
      if (detail && typeof detail === 'object' && Array.isArray(detail.errors)) {
        throw new Error(`${detail.message}: ${detail.errors.join(' | ')}`);
      }
      throw new Error(typeof detail === 'string' ? detail : 'Upload failed');
    }
    return res.json();
  }

  async uploadBatchFromGoogleSheet(url: string): Promise<BatchAnalysis> {
    const res = await fetch(`${API_BASE}/api/batch/from-url`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...this.getAuthHeaders(),
      },
      body: JSON.stringify({ url }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Google Sheets import failed' }));
      const detail = err.detail;
      if (detail && typeof detail === 'object' && Array.isArray(detail.errors)) {
        throw new Error(`${detail.message}: ${detail.errors.join(' | ')}`);
      }
      throw new Error(typeof detail === 'string' ? detail : 'Google Sheets import failed');
    }
    return res.json();
  }

  async processBatch(id: string): Promise<BatchAnalysis> {
    const res = await fetch(`${API_BASE}/api/batch/${id}/process`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Analysis failed' }));
      throw new Error(err.detail || 'Analysis failed');
    }
    return res.json();
  }

  async downloadBatchResult(batch: BatchAnalysis): Promise<void> {
    await this.downloadAuthenticatedFile(
      `${API_BASE}/api/batch/${batch.id}/result`,
      `analysed_${batch.original_filename || 'workbook.xlsx'}`
    );
  }

  async downloadBatchTemplate(): Promise<void> {
    await this.downloadAuthenticatedFile(
      `${API_BASE}/api/batch/template`,
      'certificateguard_batch_template.xlsx'
    );
  }

  private async downloadAuthenticatedFile(url: string, filename: string): Promise<void> {
    const res = await fetch(url, { headers: this.getAuthHeaders() });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Download failed' }));
      throw new Error(err.detail || 'Download failed');
    }
    const blob = await res.blob();
    const href = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = href;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(href);
  }
}

export const api = new ApiService();
