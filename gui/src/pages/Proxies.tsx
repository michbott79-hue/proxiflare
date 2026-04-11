import { useState, useEffect, useCallback } from 'react';
import type { Proxy, ProxyType, HealthStatus } from '../lib/types';
import * as api from '../lib/api';

const PROXY_TYPES: ProxyType[] = ['socks5', 'socks4', 'http', 'ssh'];

const TYPE_COLORS: Record<ProxyType, string> = {
  socks5: 'bg-[#6366f1]/20 text-[#818cf8]',
  socks4: 'bg-[#8b5cf6]/20 text-[#a78bfa]',
  http: 'bg-[#22c55e]/20 text-[#4ade80]',
  ssh: 'bg-[#f59e0b]/20 text-[#fbbf24]',
};

const HEALTH_DOT: Record<HealthStatus, string> = {
  unknown: 'bg-[#64748b]',
  online: 'bg-[#22c55e]',
  offline: 'bg-[#ef4444]',
  slow: 'bg-[#f59e0b]',
  error: 'bg-[#ef4444]',
};

interface ModalState {
  open: boolean;
  proxy: Partial<Proxy> | null;
}

const EMPTY_PROXY: Partial<Proxy> = {
  name: '',
  type: 'socks5',
  host: '',
  port: 1080,
  username: '',
  password: '',
  enabled: true,
  check_interval: 60,
};

export default function Proxies() {
  const [proxies, setProxies] = useState<Proxy[]>([]);
  const [modal, setModal] = useState<ModalState>({ open: false, proxy: null });
  const [testing, setTesting] = useState<Record<number, boolean>>({});
  const [testResults, setTestResults] = useState<Record<number, { ok: boolean; latency_ms: number | null; error?: string }>>({});
  const [saving, setSaving] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [typeDropdown, setTypeDropdown] = useState(false);

  const load = useCallback(async () => {
    try {
      const result = await api.proxyList();
      setProxies(Array.isArray(result) ? result : []);
    } catch {
      setProxies([]);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  async function handleSave() {
    if (!modal.proxy) return;
    setSaving(true);
    try {
      if ('id' in modal.proxy && modal.proxy.id !== undefined) {
        await api.proxyEdit(modal.proxy as Proxy);
      } else {
        await api.proxyAdd(modal.proxy as Omit<Proxy, 'id' | 'health' | 'latency_ms'>);
      }
      setModal({ open: false, proxy: null });
      await load();
    } catch (e) {
      console.error('Save proxy error:', e);
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(id: number) {
    try {
      await api.proxyDelete(id);
      await load();
    } catch (e) {
      console.error('Delete proxy error:', e);
    }
  }

  async function handleTest(id: number) {
    setTesting(prev => ({ ...prev, [id]: true }));
    setTestResults(prev => { const n = { ...prev }; delete n[id]; return n; });
    try {
      const result = await api.proxyTest(id);
      setTestResults(prev => ({ ...prev, [id]: result }));
    } catch (e) {
      setTestResults(prev => ({ ...prev, [id]: { ok: false, latency_ms: null, error: String(e) } }));
    } finally {
      setTesting(prev => ({ ...prev, [id]: false }));
    }
  }

  async function handleToggle(proxy: Proxy) {
    try {
      await api.proxyEdit({ ...proxy, enabled: !proxy.enabled });
      await load();
    } catch (e) {
      console.error('Toggle proxy error:', e);
    }
  }

  function updateModal(field: string, value: unknown) {
    setModal(prev => ({
      ...prev,
      proxy: prev.proxy ? { ...prev.proxy, [field]: value } : null,
    }));
  }

  return (
    <div>
      {/* Top bar */}
      <div className="mb-4 flex items-center gap-3">
        <button
          onClick={() => setModal({ open: true, proxy: { ...EMPTY_PROXY } })}
          className="rounded-md bg-[#6366f1] px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-[#818cf8]"
        >
          Add Proxy
        </button>
        <button className="rounded-md border border-[#2d3348] bg-[#232733] px-4 py-2 text-sm text-[#64748b] transition-colors hover:text-[#e2e8f0]">
          Import
        </button>
        <button className="rounded-md border border-[#2d3348] bg-[#232733] px-4 py-2 text-sm text-[#64748b] transition-colors hover:text-[#e2e8f0]">
          Export
        </button>
      </div>

      {/* Proxy grid */}
      {proxies.length === 0 ? (
        <div className="flex h-64 items-center justify-center text-[#64748b]">
          <div className="text-center">
            <p className="text-lg">No proxies configured</p>
            <p className="mt-1 text-sm">Add a proxy to get started</p>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {proxies.map(proxy => (
            <div
              key={proxy.id}
              className="rounded-lg border border-[#2d3348] bg-[#1a1d27] p-4"
            >
              {/* Card header */}
              <div className="mb-3 flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="font-medium">{proxy.name}</h3>
                    <span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ${TYPE_COLORS[proxy.type]}`}>
                      {proxy.type}
                    </span>
                  </div>
                  <p className="mt-0.5 text-sm text-[#64748b]">{proxy.host}:{proxy.port}</p>
                </div>
                <button
                  onClick={() => handleToggle(proxy)}
                  className={`relative h-5 w-9 rounded-full transition-colors ${
                    proxy.enabled ? 'bg-[#6366f1]' : 'bg-[#2d3348]'
                  }`}
                >
                  <span
                    className={`absolute top-0.5 left-0.5 h-4 w-4 rounded-full bg-white transition-transform ${
                      proxy.enabled ? 'translate-x-4' : 'translate-x-0'
                    }`}
                  />
                </button>
              </div>

              {/* Health */}
              <div className="mb-3 flex items-center gap-2 text-sm text-[#64748b]">
                <span className={`inline-block h-2 w-2 rounded-full ${HEALTH_DOT[proxy.health]}`} />
                <span className="capitalize">{proxy.health}</span>
                {proxy.latency_ms !== null && (
                  <span className="ml-auto">{proxy.latency_ms}ms</span>
                )}
              </div>

              {/* Test result */}
              {testResults[proxy.id] && (
                <div className={`mb-3 rounded px-2 py-1 text-xs ${
                  testResults[proxy.id].ok
                    ? 'bg-[#22c55e]/10 text-[#22c55e]'
                    : 'bg-[#ef4444]/10 text-[#ef4444]'
                }`}>
                  {testResults[proxy.id].ok
                    ? `OK - ${testResults[proxy.id].latency_ms}ms`
                    : testResults[proxy.id].error || 'Test failed'}
                </div>
              )}

              {/* Actions */}
              <div className="flex gap-2">
                <button
                  onClick={() => setModal({ open: true, proxy: { ...proxy } })}
                  className="rounded border border-[#2d3348] bg-[#232733] px-3 py-1.5 text-xs text-[#64748b] transition-colors hover:text-[#e2e8f0]"
                >
                  Edit
                </button>
                <button
                  onClick={() => handleTest(proxy.id)}
                  disabled={testing[proxy.id]}
                  className="rounded border border-[#2d3348] bg-[#232733] px-3 py-1.5 text-xs text-[#64748b] transition-colors hover:text-[#e2e8f0] disabled:opacity-50"
                >
                  {testing[proxy.id] ? (
                    <span className="inline-flex items-center gap-1">
                      <svg className="h-3 w-3 animate-spin" viewBox="0 0 24 24" fill="none">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                      </svg>
                      Testing
                    </span>
                  ) : 'Test'}
                </button>
                <button
                  onClick={() => handleDelete(proxy.id)}
                  className="rounded border border-[#ef4444]/30 px-3 py-1.5 text-xs text-[#ef4444] transition-colors hover:bg-[#ef4444]/10"
                >
                  Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Add/Edit modal */}
      {modal.open && modal.proxy && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-lg border border-[#2d3348] bg-[#1a1d27] p-6 shadow-2xl">
            <h2 className="mb-4 text-lg font-semibold">
              {modal.proxy.id ? 'Edit Proxy' : 'Add Proxy'}
            </h2>

            <div className="space-y-3">
              <div>
                <label className="mb-1 block text-xs text-[#64748b]">Name</label>
                <input
                  type="text"
                  value={modal.proxy.name || ''}
                  onChange={e => updateModal('name', e.target.value)}
                  className="w-full rounded-md border border-[#2d3348] bg-[#232733] px-3 py-2 text-sm text-[#e2e8f0] outline-none focus:border-[#6366f1]"
                />
              </div>

              <div className="relative">
                <label className="mb-1 block text-xs text-[#64748b]">Type</label>
                <button
                  type="button"
                  onClick={() => setTypeDropdown(p => !p)}
                  className="flex w-full items-center justify-between rounded-md border border-[#2d3348] bg-[#232733] px-3 py-2 text-sm text-[#e2e8f0] outline-none focus:border-[#6366f1]"
                >
                  <span>{(modal.proxy.type || 'socks5').toUpperCase()}</span>
                  <svg className="h-4 w-4 text-[#64748b]" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z" clipRule="evenodd" />
                  </svg>
                </button>
                {typeDropdown && (
                  <div className="absolute z-50 mt-1 w-full rounded-md border border-[#2d3348] bg-[#232733] py-1 shadow-xl">
                    {PROXY_TYPES.map(t => (
                      <button
                        key={t}
                        type="button"
                        onClick={() => { updateModal('type', t); setTypeDropdown(false); }}
                        className={`block w-full px-3 py-2 text-left text-sm transition-colors hover:bg-[#6366f1] hover:text-white ${
                          modal.proxy?.type === t ? 'bg-[#6366f1]/20 text-[#818cf8]' : 'text-[#e2e8f0]'
                        }`}
                      >
                        {t.toUpperCase()}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2">
                  <label className="mb-1 block text-xs text-[#64748b]">Host</label>
                  <input
                    type="text"
                    value={modal.proxy.host || ''}
                    onChange={e => updateModal('host', e.target.value)}
                    className="w-full rounded-md border border-[#2d3348] bg-[#232733] px-3 py-2 text-sm text-[#e2e8f0] outline-none focus:border-[#6366f1]"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs text-[#64748b]">Port</label>
                  <input
                    type="number"
                    value={modal.proxy.port || 1080}
                    onChange={e => updateModal('port', parseInt(e.target.value) || 0)}
                    className="w-full rounded-md border border-[#2d3348] bg-[#232733] px-3 py-2 text-sm text-[#e2e8f0] outline-none focus:border-[#6366f1]"
                  />
                </div>
              </div>

              <div>
                <label className="mb-1 block text-xs text-[#64748b]">Username (optional)</label>
                <input
                  type="text"
                  value={modal.proxy.username || ''}
                  onChange={e => updateModal('username', e.target.value)}
                  className="w-full rounded-md border border-[#2d3348] bg-[#232733] px-3 py-2 text-sm text-[#e2e8f0] outline-none focus:border-[#6366f1]"
                />
              </div>

              <div className="relative">
                <label className="mb-1 block text-xs text-[#64748b]">Password (optional)</label>
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={modal.proxy.password || ''}
                  onChange={e => updateModal('password', e.target.value)}
                  className="w-full rounded-md border border-[#2d3348] bg-[#232733] px-3 py-2 pr-9 text-sm text-[#e2e8f0] outline-none focus:border-[#6366f1]"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(p => !p)}
                  className="absolute top-7 right-3 text-[#64748b] hover:text-[#e2e8f0]"
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    {showPassword ? (
                      <>
                        <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
                        <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
                        <line x1="1" y1="1" x2="23" y2="23" />
                      </>
                    ) : (
                      <>
                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                        <circle cx="12" cy="12" r="3" />
                      </>
                    )}
                  </svg>
                </button>
              </div>

              <div>
                <label className="mb-1 block text-xs text-[#64748b]">Check Interval (seconds)</label>
                <input
                  type="number"
                  value={modal.proxy.check_interval || 60}
                  onChange={e => updateModal('check_interval', parseInt(e.target.value) || 60)}
                  className="w-full rounded-md border border-[#2d3348] bg-[#232733] px-3 py-2 text-sm text-[#e2e8f0] outline-none focus:border-[#6366f1]"
                />
              </div>
            </div>

            <div className="mt-6 flex justify-end gap-3">
              <button
                onClick={() => { setModal({ open: false, proxy: null }); setShowPassword(false); }}
                className="rounded-md border border-[#2d3348] bg-[#232733] px-4 py-2 text-sm text-[#64748b] transition-colors hover:text-[#e2e8f0]"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={saving || !modal.proxy.name || !modal.proxy.host}
                className="rounded-md bg-[#6366f1] px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-[#818cf8] disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {saving ? 'Saving...' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
