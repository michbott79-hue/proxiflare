import { useState, useEffect, useCallback } from 'react';
import type { Chain, Proxy } from '../lib/types';
import * as api from '../lib/api';

interface EditState {
  open: boolean;
  chain: { id?: number; name: string; enabled: boolean; hop_proxy_ids: number[] } | null;
}

export default function Chains() {
  const [chains, setChains] = useState<Chain[]>([]);
  const [proxies, setProxies] = useState<Proxy[]>([]);
  const [edit, setEdit] = useState<EditState>({ open: false, chain: null });
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState<Record<number, boolean>>({});
  const [testResults, setTestResults] = useState<Record<number, { ok: boolean; latency_ms: number | null; error?: string }>>({});

  const load = useCallback(async () => {
    try {
      const [c, p] = await Promise.all([api.chainList(), api.proxyList()]);
      setChains(Array.isArray(c) ? c : []);
      setProxies(Array.isArray(p) ? p : []);
    } catch {
      setChains([]); setProxies([]);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  function getProxyName(id: number) {
    return proxies.find(p => p.id === id)?.name || `#${id}`;
  }

  async function handleSave() {
    if (!edit.chain) return;
    setSaving(true);
    try {
      if (edit.chain.id !== undefined) {
        await api.chainEdit(edit.chain as Chain);
      } else {
        await api.chainAdd({ name: edit.chain.name, enabled: edit.chain.enabled, hop_proxy_ids: edit.chain.hop_proxy_ids });
      }
      setEdit({ open: false, chain: null });
      await load();
    } catch (e) {
      console.error('Save chain error:', e);
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(id: number) {
    try {
      await api.chainDelete(id);
      await load();
    } catch (e) {
      console.error('Delete chain error:', e);
    }
  }

  async function handleTest(id: number) {
    setTesting(prev => ({ ...prev, [id]: true }));
    setTestResults(prev => { const n = { ...prev }; delete n[id]; return n; });
    try {
      const result = await api.chainTest(id);
      setTestResults(prev => ({ ...prev, [id]: result }));
    } catch (e) {
      setTestResults(prev => ({ ...prev, [id]: { ok: false, latency_ms: null, error: String(e) } }));
    } finally {
      setTesting(prev => ({ ...prev, [id]: false }));
    }
  }

  function addHop() {
    if (!edit.chain || proxies.length === 0) return;
    setEdit(prev => ({
      ...prev,
      chain: prev.chain
        ? { ...prev.chain, hop_proxy_ids: [...prev.chain.hop_proxy_ids, proxies[0].id] }
        : null,
    }));
  }

  function removeHop(idx: number) {
    setEdit(prev => ({
      ...prev,
      chain: prev.chain
        ? { ...prev.chain, hop_proxy_ids: prev.chain.hop_proxy_ids.filter((_, i) => i !== idx) }
        : null,
    }));
  }

  function moveHop(idx: number, dir: -1 | 1) {
    if (!edit.chain) return;
    const hops = [...edit.chain.hop_proxy_ids];
    const target = idx + dir;
    if (target < 0 || target >= hops.length) return;
    [hops[idx], hops[target]] = [hops[target], hops[idx]];
    setEdit(prev => ({
      ...prev,
      chain: prev.chain ? { ...prev.chain, hop_proxy_ids: hops } : null,
    }));
  }

  function updateHop(idx: number, proxyId: number) {
    setEdit(prev => ({
      ...prev,
      chain: prev.chain
        ? { ...prev.chain, hop_proxy_ids: prev.chain.hop_proxy_ids.map((h, i) => i === idx ? proxyId : h) }
        : null,
    }));
  }

  return (
    <div>
      {/* Top bar */}
      <div className="mb-4 flex items-center gap-3">
        <button
          onClick={() => setEdit({ open: true, chain: { name: '', enabled: true, hop_proxy_ids: [] } })}
          className="rounded-md bg-[#6366f1] px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-[#818cf8]"
        >
          Create Chain
        </button>
      </div>

      {/* Chain list */}
      {chains.length === 0 ? (
        <div className="flex h-64 items-center justify-center text-[#64748b]">
          <div className="text-center">
            <p className="text-lg">No chains configured</p>
            <p className="mt-1 text-sm">Create a chain to route traffic through multiple proxies</p>
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          {chains.map(chain => (
            <div
              key={chain.id}
              className="rounded-lg border border-[#2d3348] bg-[#1a1d27] p-4"
            >
              <div className="mb-3 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <h3 className="font-medium">{chain.name}</h3>
                  <span className="text-xs text-[#64748b]">
                    {chain.hop_proxy_ids.length} hop{chain.hop_proxy_ids.length !== 1 ? 's' : ''}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleTest(chain.id)}
                    disabled={testing[chain.id]}
                    className="rounded border border-[#2d3348] bg-[#232733] px-3 py-1.5 text-xs text-[#64748b] transition-colors hover:text-[#e2e8f0] disabled:opacity-50"
                  >
                    {testing[chain.id] ? (
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
                    onClick={() => setEdit({ open: true, chain: { ...chain } })}
                    className="rounded border border-[#2d3348] bg-[#232733] px-3 py-1.5 text-xs text-[#64748b] transition-colors hover:text-[#e2e8f0]"
                  >
                    Edit
                  </button>
                  <button
                    onClick={() => handleDelete(chain.id)}
                    className="rounded border border-[#ef4444]/30 px-3 py-1.5 text-xs text-[#ef4444] transition-colors hover:bg-[#ef4444]/10"
                  >
                    Delete
                  </button>
                </div>
              </div>

              {/* Hop chain visualization */}
              <div className="flex flex-wrap items-center gap-1">
                {chain.hop_proxy_ids.map((proxyId, idx) => (
                  <div key={idx} className="flex items-center gap-1">
                    <span className="rounded bg-[#6366f1]/20 px-2.5 py-1 text-xs font-medium text-[#818cf8]">
                      {getProxyName(proxyId)}
                    </span>
                    {idx < chain.hop_proxy_ids.length - 1 && (
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#64748b" strokeWidth="2">
                        <path d="M5 12h14M12 5l7 7-7 7" />
                      </svg>
                    )}
                  </div>
                ))}
                {chain.hop_proxy_ids.length === 0 && (
                  <span className="text-xs text-[#64748b]">No hops</span>
                )}
              </div>

              {/* Test result */}
              {testResults[chain.id] && (
                <div className={`mt-3 rounded px-2 py-1 text-xs ${
                  testResults[chain.id].ok
                    ? 'bg-[#22c55e]/10 text-[#22c55e]'
                    : 'bg-[#ef4444]/10 text-[#ef4444]'
                }`}>
                  {testResults[chain.id].ok
                    ? `OK - ${testResults[chain.id].latency_ms}ms`
                    : testResults[chain.id].error || 'Test failed'}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Create/Edit modal */}
      {edit.open && edit.chain && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-lg border border-[#2d3348] bg-[#1a1d27] p-6 shadow-2xl">
            <h2 className="mb-4 text-lg font-semibold">
              {edit.chain.id !== undefined ? 'Edit Chain' : 'Create Chain'}
            </h2>

            <div className="space-y-4">
              <div>
                <label className="mb-1 block text-xs text-[#64748b]">Name</label>
                <input
                  type="text"
                  value={edit.chain.name}
                  onChange={e => setEdit(prev => ({
                    ...prev,
                    chain: prev.chain ? { ...prev.chain, name: e.target.value } : null,
                  }))}
                  className="w-full rounded-md border border-[#2d3348] bg-[#232733] px-3 py-2 text-sm text-[#e2e8f0] outline-none focus:border-[#6366f1]"
                />
              </div>

              <div>
                <div className="mb-2 flex items-center justify-between">
                  <label className="text-xs text-[#64748b]">Hops</label>
                  <button
                    onClick={addHop}
                    disabled={proxies.length === 0}
                    className="rounded bg-[#232733] px-2.5 py-1 text-xs text-[#64748b] transition-colors hover:text-[#e2e8f0] disabled:opacity-50"
                  >
                    + Add Hop
                  </button>
                </div>

                {edit.chain.hop_proxy_ids.length === 0 ? (
                  <p className="rounded border border-dashed border-[#2d3348] py-4 text-center text-xs text-[#64748b]">
                    No hops added. Add proxies to build the chain.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {edit.chain.hop_proxy_ids.map((proxyId, idx) => (
                      <div key={idx} className="flex items-center gap-2">
                        <span className="w-6 text-center text-xs text-[#64748b]">{idx + 1}</span>
                        <select
                          value={proxyId}
                          onChange={e => updateHop(idx, parseInt(e.target.value))}
                          className="flex-1 rounded-md border border-[#2d3348] bg-[#232733] px-3 py-1.5 text-sm text-[#e2e8f0] outline-none focus:border-[#6366f1]"
                        >
                          {proxies.map(p => (
                            <option key={p.id} value={p.id}>{p.name} ({p.host}:{p.port})</option>
                          ))}
                        </select>
                        <button
                          onClick={() => moveHop(idx, -1)}
                          disabled={idx === 0}
                          className="rounded p-1 text-[#64748b] transition-colors hover:text-[#e2e8f0] disabled:opacity-30"
                        >
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M18 15l-6-6-6 6" />
                          </svg>
                        </button>
                        <button
                          onClick={() => moveHop(idx, 1)}
                          disabled={idx === edit.chain!.hop_proxy_ids.length - 1}
                          className="rounded p-1 text-[#64748b] transition-colors hover:text-[#e2e8f0] disabled:opacity-30"
                        >
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M6 9l6 6 6-6" />
                          </svg>
                        </button>
                        <button
                          onClick={() => removeHop(idx)}
                          className="rounded p-1 text-[#ef4444] transition-colors hover:text-[#f87171]"
                        >
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M18 6L6 18M6 6l12 12" />
                          </svg>
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            <div className="mt-6 flex justify-end gap-3">
              <button
                onClick={() => setEdit({ open: false, chain: null })}
                className="rounded-md border border-[#2d3348] bg-[#232733] px-4 py-2 text-sm text-[#64748b] transition-colors hover:text-[#e2e8f0]"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={saving || !edit.chain.name}
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
