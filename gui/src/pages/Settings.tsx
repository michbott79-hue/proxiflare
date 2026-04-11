import { useState } from 'react';
import type { DaemonStatus } from '../lib/types';
import * as api from '../lib/api';

interface DaemonState {
  status: DaemonStatus | null;
  connected: boolean;
  unlocked: boolean;
  error: string | null;
  setUnlocked: (val: boolean) => void;
  refresh: () => Promise<void>;
}

interface Props {
  daemon: DaemonState;
}

export default function Settings({ daemon }: Props) {
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [passwordMsg, setPasswordMsg] = useState('');
  const [passwordError, setPasswordError] = useState(false);
  const [locking, setLocking] = useState(false);

  async function handleChangePassword(e: React.FormEvent) {
    e.preventDefault();
    if (newPassword !== confirmPassword) {
      setPasswordMsg('Passwords do not match');
      setPasswordError(true);
      return;
    }
    if (!newPassword) {
      setPasswordMsg('Password cannot be empty');
      setPasswordError(true);
      return;
    }
    try {
      await api.configSet('master_password', JSON.stringify({ old: oldPassword, new: newPassword }));
      setPasswordMsg('Password changed successfully');
      setPasswordError(false);
      setOldPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setPasswordMsg(msg);
      setPasswordError(true);
    }
  }

  async function handleLock() {
    setLocking(true);
    try {
      await api.credentialsLock();
      daemon.setUnlocked(false);
    } catch (e) {
      console.error('Lock error:', e);
    } finally {
      setLocking(false);
    }
  }

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      {/* Daemon section */}
      <section className="rounded-lg border border-[#2d3348] bg-[#1a1d27] p-5">
        <h2 className="mb-4 text-sm font-semibold uppercase tracking-wider text-[#64748b]">Daemon</h2>
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-sm">Status</span>
            <div className="flex items-center gap-2">
              <span
                className={`inline-block h-2 w-2 rounded-full ${
                  daemon.connected
                    ? daemon.status?.running
                      ? 'bg-[#22c55e]'
                      : 'bg-[#f59e0b]'
                    : 'bg-[#ef4444]'
                }`}
              />
              <span className="text-sm text-[#64748b]">
                {daemon.connected
                  ? daemon.status?.running
                    ? 'Running'
                    : 'Stopped'
                  : 'Disconnected'}
              </span>
            </div>
          </div>
          {daemon.status && daemon.connected && (
            <>
              <div className="flex items-center justify-between">
                <span className="text-sm">Active connections</span>
                <span className="text-sm text-[#64748b]">{daemon.status.connections}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm">Proxies online</span>
                <span className="text-sm text-[#64748b]">{daemon.status.proxies_online}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm">Active rules</span>
                <span className="text-sm text-[#64748b]">{daemon.status.rules_active}</span>
              </div>
            </>
          )}
          <div className="flex items-center justify-between">
            <span className="text-sm">Start at boot</span>
            <button
              className="relative h-5 w-9 rounded-full bg-[#2d3348] transition-colors"
              title="Not yet implemented"
            >
              <span className="absolute top-0.5 left-0.5 h-4 w-4 rounded-full bg-white" />
            </button>
          </div>
        </div>
      </section>

      {/* Security section */}
      <section className="rounded-lg border border-[#2d3348] bg-[#1a1d27] p-5">
        <h2 className="mb-4 text-sm font-semibold uppercase tracking-wider text-[#64748b]">Security</h2>

        <form onSubmit={handleChangePassword} className="mb-4 space-y-3">
          <div>
            <label className="mb-1 block text-xs text-[#64748b]">Current password</label>
            <input
              type="password"
              value={oldPassword}
              onChange={e => setOldPassword(e.target.value)}
              className="w-full rounded-md border border-[#2d3348] bg-[#232733] px-3 py-2 text-sm text-[#e2e8f0] outline-none focus:border-[#6366f1]"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-[#64748b]">New password</label>
            <input
              type="password"
              value={newPassword}
              onChange={e => setNewPassword(e.target.value)}
              className="w-full rounded-md border border-[#2d3348] bg-[#232733] px-3 py-2 text-sm text-[#e2e8f0] outline-none focus:border-[#6366f1]"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-[#64748b]">Confirm new password</label>
            <input
              type="password"
              value={confirmPassword}
              onChange={e => setConfirmPassword(e.target.value)}
              className="w-full rounded-md border border-[#2d3348] bg-[#232733] px-3 py-2 text-sm text-[#e2e8f0] outline-none focus:border-[#6366f1]"
            />
          </div>
          {passwordMsg && (
            <p className={`text-sm ${passwordError ? 'text-[#ef4444]' : 'text-[#22c55e]'}`}>
              {passwordMsg}
            </p>
          )}
          <button
            type="submit"
            className="rounded-md bg-[#6366f1] px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-[#818cf8]"
          >
            Change Password
          </button>
        </form>

        <div className="border-t border-[#2d3348] pt-4">
          <button
            onClick={handleLock}
            disabled={locking}
            className="rounded-md border border-[#f59e0b]/30 px-4 py-2 text-sm text-[#f59e0b] transition-colors hover:bg-[#f59e0b]/10 disabled:opacity-50"
          >
            {locking ? 'Locking...' : 'Lock Vault'}
          </button>
        </div>
      </section>

      {/* Logging section */}
      <section className="rounded-lg border border-[#2d3348] bg-[#1a1d27] p-5">
        <h2 className="mb-4 text-sm font-semibold uppercase tracking-wider text-[#64748b]">Logging</h2>
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-sm">Log to disk</span>
            <button
              className="relative h-5 w-9 rounded-full bg-[#2d3348] transition-colors"
              title="Not yet implemented"
            >
              <span className="absolute top-0.5 left-0.5 h-4 w-4 rounded-full bg-white" />
            </button>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-sm">Log path</span>
            <span className="text-sm text-[#64748b]">~/.local/share/proxiflare/logs/</span>
          </div>
        </div>
      </section>

      {/* About section */}
      <section className="rounded-lg border border-[#2d3348] bg-[#1a1d27] p-5">
        <h2 className="mb-4 text-sm font-semibold uppercase tracking-wider text-[#64748b]">About</h2>
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-sm">Version</span>
            <span className="text-sm text-[#64748b]">
              {daemon.status?.version || 'ProxiFlare v1.0.0'}
            </span>
          </div>
        </div>
      </section>
    </div>
  );
}
