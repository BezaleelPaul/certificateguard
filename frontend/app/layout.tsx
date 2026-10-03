'use client';

import './globals.css';
import { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { 
  ShieldCheck, 
  FileUp, 
  Layers, 
  CheckCircle2, 
  FileText, 
  Building2, 
  History, 
  UserCircle2, 
  AlertTriangle 
} from 'lucide-react';
import { api } from '@/lib/api';
import { User, UserRole } from '@/types';

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const pathname = usePathname();

  useEffect(() => {
    // Initial login as Teacher for rich demo experience
    const initAuth = async () => {
      try {
        const stored = api.getCurrentUser();
        if (stored) {
          setCurrentUser(stored);
        } else {
          // Backend may be cold-starting; retry login a few times before giving up.
          let lastErr: unknown = null;
          for (let attempt = 0; attempt < 4; attempt++) {
            try {
              const { user } = await api.login('TEACHER');
              setCurrentUser(user);
              lastErr = null;
              break;
            } catch (err) {
              lastErr = err;
              await new Promise((r) => setTimeout(r, 3000));
            }
          }
          if (lastErr) throw lastErr;
        }
      } catch (err) {
        console.error('Failed to init auth:', err);
      } finally {
        setLoading(false);
      }
    };
    initAuth();
  }, []);

  const handleRoleSwitch = async (role: UserRole) => {
    try {
      const { user } = await api.login(role);
      setCurrentUser(user);
      window.location.reload();
    } catch (err) {
      alert('Failed to switch role');
    }
  };

  const isStudent = currentUser?.role === 'STUDENT';

  return (
    <html lang="en">
      <head>
        <title>CertificateGuard | Evidence-Based Certificate Verification</title>
        <meta name="description" content="AI and automation provide evidence. The issuer and teacher provide trust." />
      </head>
      <body className="font-sans antialiased text-slate-800">
        <header className="sticky top-0 z-50 bg-slate-900 border-b border-slate-800 text-white shadow-md">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex items-center justify-between h-16">
              <div className="flex items-center space-x-3">
                <Link href="/" className="flex items-center space-x-2 text-white hover:text-blue-400 transition-colors">
                  <div className="p-2 bg-blue-600 rounded-lg">
                    <ShieldCheck className="h-6 w-6 text-white" />
                  </div>
                  <div>
                    <span className="font-bold text-lg tracking-tight">CERTIFICATEGUARD</span>
                    <span className="hidden sm:inline-block ml-2 text-xs uppercase px-2 py-0.5 rounded bg-blue-900 text-blue-300 font-semibold border border-blue-700">
                      College Authority
                    </span>
                  </div>
                </Link>
              </div>

              {/* Navigation Links */}
              <nav className="hidden md:flex space-x-1">
                <Link
                  href="/"
                  className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    pathname === '/' ? 'bg-slate-800 text-white' : 'text-slate-300 hover:bg-slate-800 hover:text-white'
                  }`}
                >
                  Dashboard
                </Link>
                <Link
                  href="/submit"
                  className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    pathname === '/submit' ? 'bg-slate-800 text-white' : 'text-slate-300 hover:bg-slate-800 hover:text-white'
                  }`}
                >
                  Submit Certificate
                </Link>
                <Link
                  href="/batch"
                  className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    pathname === '/batch' ? 'bg-slate-800 text-white' : 'text-slate-300 hover:bg-slate-800 hover:text-white'
                  }`}
                >
                  Batch Analysis
                </Link>
                {!isStudent && (
                  <>
                    <Link
                      href="/issuers"
                      className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                        pathname === '/issuers' ? 'bg-slate-800 text-white' : 'text-slate-300 hover:bg-slate-800 hover:text-white'
                      }`}
                    >
                      Issuers Registry
                    </Link>
                    <Link
                      href="/audit"
                      className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                        pathname === '/audit' ? 'bg-slate-800 text-white' : 'text-slate-300 hover:bg-slate-800 hover:text-white'
                      }`}
                    >
                      Audit Logs
                    </Link>
                  </>
                )}
              </nav>

              {/* Role Switcher for Evaluation */}
              <div className="flex items-center space-x-3">
                <div className="flex items-center bg-slate-800 px-3 py-1.5 rounded-lg border border-slate-700 text-xs text-slate-300">
                  <UserCircle2 className="w-4 h-4 mr-1.5 text-blue-400" />
                  <span className="font-semibold text-white mr-2">{currentUser?.name || 'Loading...'}</span>
                  <select
                    className="bg-slate-900 text-blue-300 border border-slate-700 rounded px-2 py-0.5 text-xs focus:ring-1 focus:ring-blue-500 outline-none"
                    value={currentUser?.role || 'TEACHER'}
                    onChange={(e) => handleRoleSwitch(e.target.value as UserRole)}
                  >
                    <option value="TEACHER">Teacher Role</option>
                    <option value="STUDENT">Student Role</option>
                    <option value="ADMIN">Admin Role</option>
                  </select>
                </div>
              </div>
            </div>
          </div>
        </header>

        {/* Philosophy Banner */}
        <div className="bg-blue-50 border-b border-blue-100 text-blue-900 px-4 py-1.5 text-xs text-center font-medium">
          « AI and automation provide evidence. The issuer and teacher provide trust. »
        </div>

        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {loading ? (
            <div className="flex flex-col items-center justify-center min-h-[50vh]">
              <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
              <p className="mt-4 text-sm text-slate-500 font-medium">
                Connecting to CertificateGuard...
              </p>
            </div>
          ) : (
            children
          )}
        </main>
      </body>
    </html>
  );
}
