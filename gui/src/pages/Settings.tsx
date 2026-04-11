import { useState, useEffect, useRef } from 'react';
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

const DNS_PRESETS = [
  { label: 'Cloudflare',  value: '1.1.1.1' },
  { label: 'Google',      value: '8.8.8.8' },
  { label: 'Quad9',       value: '9.9.9.9' },
  { label: 'OpenDNS',     value: '208.67.222.222' },
  { label: 'Custom',      value: 'custom' },
];

export default function Settings({ daemon }: Props) {
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [passwordMsg, setPasswordMsg] = useState('');
  const [passwordError, setPasswordError] = useState(false);
  const [locking, setLocking] = useState(false);

  /* Boot at startup state */
  const [bootEnabled, setBootEnabled]     = useState(false);
  const [bootToggling, setBootToggling]   = useState(false);

  /* Log to disk state */
  const [logDisk, setLogDisk]             = useState(true);
  const [logToggling, setLogToggling]     = useState(false);

  /* DNS leak protection state */
  const [dnsEnabled, setDnsEnabled]       = useState(false);
  const [dnsServer, setDnsServer]         = useState('1.1.1.1');
  const [dnsCustom, setDnsCustom]         = useState('');
  const [dnsDropOpen, setDnsDropOpen]     = useState(false);
  const [dnsToggling, setDnsToggling]     = useState(false);
  const dnsDropRef                        = useRef<HTMLDivElement>(null);

  /* Derive selected preset label */
  const selectedPreset = DNS_PRESETS.find(p => p.value === dnsServer) ?? DNS_PRESETS[4];
  const effectiveDns   = dnsServer === 'custom' ? dnsCustom : dnsServer;

  useEffect(() => {
    if (!daemon.connected) return;
    api.dnsLeakStatus()
      .then(s => {
        setDnsEnabled(s.enabled);
        const preset = DNS_PRESETS.find(p => p.value === s.dns_server);
        if (preset) {
          setDnsServer(s.dns_server);
        } else if (s.dns_server) {
          setDnsServer('custom');
          setDnsCustom(s.dns_server);
        }
      })
      .catch(() => {});
    api.configGet('boot_enabled')
      .then(v => setBootEnabled(v === 'true' || v === '1'))
      .catch(() => {});
    api.configGet('log_disk_enabled')
      .then(v => setLogDisk(v !== 'false' && v !== '0'))
      .catch(() => {});
  }, [daemon.connected]);

  /* Close dropdown on outside click */
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (dnsDropRef.current && !dnsDropRef.current.contains(e.target as Node)) {
        setDnsDropOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, []);

  async function handleDnsToggle() {
    setDnsToggling(true);
    try {
      if (dnsEnabled) {
        await api.dnsLeakDisable();
        setDnsEnabled(false);
      } else {
        await api.dnsLeakEnable(effectiveDns);
        setDnsEnabled(true);
      }
    } catch (e) {
      console.error('DNS leak toggle error:', e);
    } finally {
      setDnsToggling(false);
    }
  }

  async function handleDnsServerChange(value: string) {
    setDnsServer(value);
    setDnsDropOpen(false);
    if (value === 'custom') return;
    /* If already enabled, update the active server immediately */
    if (dnsEnabled) {
      try {
        await api.dnsLeakEnable(value);
      } catch (e) {
        console.error('DNS server update error:', e);
      }
    }
  }

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
              onClick={async () => {
                setBootToggling(true);
                try {
                  const next = !bootEnabled;
                  await api.configSet('boot_enabled', next ? 'true' : 'false');
                  setBootEnabled(next);
                } catch (e) { console.error('Boot toggle error:', e); }
                finally { setBootToggling(false); }
              }}
              disabled={bootToggling}
              className={`relative h-5 w-9 rounded-full transition-colors disabled:opacity-50 ${
                bootEnabled ? 'bg-[#6366f1]' : 'bg-[#2d3348]'
              }`}
            >
              <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-white transition-all ${
                bootEnabled ? 'left-[calc(100%-1.125rem)]' : 'left-0.5'
              }`} />
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

      {/* DNS Leak Protection section */}
      <section className="rounded-lg border border-[#2d3348] bg-[#1a1d27] p-5">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-[#64748b]">DNS Leak Protection</h2>
          {dnsEnabled && (
            <span className="flex items-center gap-1.5 text-xs text-[#22c55e]">
              <span className="inline-block h-2 w-2 rounded-full bg-[#22c55e]" />
              Active
            </span>
          )}
        </div>
        <p className="mb-4 text-xs text-[#64748b]">
          Prevents DNS queries from leaking to your ISP. All DNS is redirected to a secure server.
        </p>
        <div className="space-y-4">
          {/* Toggle */}
          <div className="flex items-center justify-between">
            <span className="text-sm">Enable protection</span>
            <button
              onClick={handleDnsToggle}
              disabled={dnsToggling}
              className={`relative h-5 w-9 rounded-full transition-colors disabled:opacity-50 ${
                dnsEnabled ? 'bg-[#6366f1]' : 'bg-[#2d3348]'
              }`}
            >
              <span
                className={`absolute top-0.5 h-4 w-4 rounded-full bg-white transition-all ${
                  dnsEnabled ? 'left-[calc(100%-1.125rem)]' : 'left-0.5'
                }`}
              />
            </button>
          </div>

          {/* DNS Server selector */}
          <div className="flex items-center justify-between">
            <span className="text-sm">DNS Server</span>
            <div className="relative" ref={dnsDropRef}>
              <button
                onClick={() => setDnsDropOpen(v => !v)}
                className="flex items-center gap-2 rounded-md border border-[#2d3348] bg-[#232733] px-3 py-1.5 text-sm text-[#e2e8f0] transition-colors hover:border-[#6366f1]"
              >
                <span>{selectedPreset.label}</span>
                <svg className="h-3 w-3 text-[#64748b]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </button>
              {dnsDropOpen && (
                <div className="absolute right-0 z-50 mt-1 min-w-[180px] rounded-md border border-[#2d3348] bg-[#1a1d27] py-1 shadow-lg">
                  {DNS_PRESETS.map(preset => (
                    <button
                      key={preset.value}
                      onClick={() => handleDnsServerChange(preset.value)}
                      className={`flex w-full items-center justify-between px-3 py-2 text-left text-sm transition-colors hover:bg-[#2d3348] ${
                        dnsServer === preset.value ? 'text-[#6366f1]' : 'text-[#e2e8f0]'
                      }`}
                    >
                      <span>{preset.label}</span>
                      {preset.value !== 'custom' && (
                        <span className="text-xs text-[#64748b]">{preset.value}</span>
                      )}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Custom DNS input */}
          {dnsServer === 'custom' && (
            <div className="flex items-center gap-3">
              <input
                type="text"
                value={dnsCustom}
                onChange={e => setDnsCustom(e.target.value)}
                placeholder="e.g. 94.140.14.14"
                className="flex-1 rounded-md border border-[#2d3348] bg-[#232733] px-3 py-1.5 text-sm text-[#e2e8f0] outline-none focus:border-[#6366f1]"
              />
              {dnsEnabled && (
                <button
                  onClick={() => api.dnsLeakEnable(dnsCustom).catch(console.error)}
                  className="rounded-md bg-[#6366f1] px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-[#818cf8]"
                >
                  Apply
                </button>
              )}
            </div>
          )}
        </div>
      </section>

      {/* Logging section */}
      <section className="rounded-lg border border-[#2d3348] bg-[#1a1d27] p-5">
        <h2 className="mb-4 text-sm font-semibold uppercase tracking-wider text-[#64748b]">Logging</h2>
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-sm">Log to disk</span>
            <button
              onClick={async () => {
                setLogToggling(true);
                try {
                  const next = !logDisk;
                  await api.configSet('log_disk_enabled', next ? 'true' : 'false');
                  setLogDisk(next);
                } catch (e) { console.error('Log toggle error:', e); }
                finally { setLogToggling(false); }
              }}
              disabled={logToggling}
              className={`relative h-5 w-9 rounded-full transition-colors disabled:opacity-50 ${
                logDisk ? 'bg-[#6366f1]' : 'bg-[#2d3348]'
              }`}
            >
              <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-white transition-all ${
                logDisk ? 'left-[calc(100%-1.125rem)]' : 'left-0.5'
              }`} />
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
              {daemon.status?.version || '0.1.0-alpha'}
            </span>
          </div>
        </div>
      </section>
    </div>
  );
}
