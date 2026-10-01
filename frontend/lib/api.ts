import { User, Submission, Issuer, AuditLog, PlatformStats, TeacherDecision, UserRole } from '@/types';

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
}

export const api = new ApiService();
