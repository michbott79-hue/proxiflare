import { useState } from 'react';
import { credentialsUnlock } from '../lib/api';

interface Props {
  onUnlocked: () => void;
}

export default function MasterPasswordDialog({ onUnlocked }: Props) {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!password.trim()) return;

    setLoading(true);
    setError('');

    try {
      const ok = await credentialsUnlock(password);
      if (ok) {
        onUnlocked();
      } else {
        setError('Invalid password');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-sm rounded-lg border border-[#2d3348] bg-[#1a1d27] p-8 shadow-2xl"
      >
        <div className="mb-6 text-center">
          <h1 className="text-xl font-bold text-[#e2e8f0]">ProxiFlare</h1>
          <p className="mt-1 text-sm text-[#64748b]">Enter Master Password</p>
        </div>

        <div className="relative mb-4">
          <input
            type={showPassword ? 'text' : 'password'}
            value={password}
            onChange={e => setPassword(e.target.value)}
            placeholder="Master password"
            autoFocus
            className="w-full rounded-md border border-[#2d3348] bg-[#232733] px-4 py-2.5 pr-10 text-sm text-[#e2e8f0] placeholder-[#64748b] outline-none focus:border-[#6366f1]"
          />
          <button
            type="button"
            onClick={() => setShowPassword(p => !p)}
            className="absolute top-1/2 right-3 -translate-y-1/2 text-[#64748b] hover:text-[#e2e8f0]"
            tabIndex={-1}
          >
            {showPassword ? (
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
                <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
                <line x1="1" y1="1" x2="23" y2="23" />
              </svg>
            ) : (
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                <circle cx="12" cy="12" r="3" />
              </svg>
            )}
          </button>
        </div>

        {error && (
          <p className="mb-4 text-sm text-[#ef4444]">{error}</p>
        )}

        <button
          type="submit"
          disabled={loading || !password.trim()}
          className="w-full rounded-md bg-[#6366f1] px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-[#818cf8] disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? 'Unlocking...' : 'Unlock'}
        </button>
      </form>
    </div>
  );
}
