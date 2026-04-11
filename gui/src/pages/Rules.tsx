import { useState, useEffect, useCallback, useRef } from 'react';
import type { Rule, RuleAction, Proxy, Chain } from '../lib/types';
import * as api from '../lib/api';
import type { SystemApp } from '../lib/api';

const ACTIONS: RuleAction[] = ['DIRECT', 'PROXY', 'CHAIN', 'BLOCK', 'REJECT'];

const ACTION_COLORS: Record<RuleAction, string> = {
  DIRECT: 'bg-[#64748b]/20 text-[#94a3b8]',
  PROXY: 'bg-[#6366f1]/20 text-[#818cf8]',
  CHAIN: 'bg-[#a855f7]/20 text-[#c084fc]',
  BLOCK: 'bg-[#ef4444]/20 text-[#f87171]',
  REJECT: 'bg-[#f59e0b]/20 text-[#fbbf24]',
};

const MATCH_BADGE = {
  app: 'bg-[#3b82f6]/20 text-[#60a5fa]',
  domain: 'bg-[#22c55e]/20 text-[#4ade80]',
  ip: 'bg-[#f59e0b]/20 text-[#fbbf24]',
  port: 'bg-[#06b6d4]/20 text-[#22d3ee]',
};

interface ModalState {
  open: boolean;
  rule: Partial<Rule> | null;
}

const EMPTY_RULE: Partial<Rule> = {
  name: '',
  enabled: true,
  priority: 100,
  match_app: '',
  match_domain: '',
  match_ip: '',
  match_port: '',
  action: 'DIRECT',
  proxy_id: undefined,
  chain_id: undefined,
};

export default function Rules() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [proxies, setProxies] = useState<Proxy[]>([]);
  const [chains, setChains] = useState<Chain[]>([]);
  const [modal, setModal] = useState<ModalState>({ open: false, rule: null });
  const [saving, setSaving] = useState(false);
  const dragItem = useRef<number | null>(null);
  const dragOver = useRef<number | null>(null);

  // App picker state
  const [systemApps, setSystemApps] = useState<SystemApp[]>([]);
  const [appSearch, setAppSearch] = useState('');
  const [showAppPicker, setShowAppPicker] = useState(false);

  // Custom dropdown states
  const [showActionDd, setShowActionDd] = useState(false);
  const [showProxyDd, setShowProxyDd] = useState(false);
  const [showChainDd, setShowChainDd] = useState(false);

  const load = useCallback(async () => {
    try {
      const [r, p, c] = await Promise.all([
        api.ruleList(),
        api.proxyList(),
        api.chainList(),
      ]);
      setRules(Array.isArray(r) ? r : []);
      setProxies(Array.isArray(p) ? p : []);
      setChains(Array.isArray(c) ? c : []);
    } catch {
      setRules([]); setProxies([]); setChains([]);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // Load system apps when modal opens
  useEffect(() => {
    if (modal.open) {
      api.listSystemApps().then(apps => {
        setSystemApps(Array.isArray(apps) ? apps : []);
      }).catch(() => setSystemApps([]));
    }
  }, [modal.open]);

  async function handleSave() {
    if (!modal.rule) return;
    setSaving(true);
    try {
      if ('id' in modal.rule && modal.rule.id !== undefined) {
        await api.ruleEdit(modal.rule as Rule);
      } else {
        await api.ruleAdd(modal.rule as Omit<Rule, 'id'>);
      }
      setModal({ open: false, rule: null });
      await load();
    } catch (e) {
      console.error('Save rule error:', e);
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(id: number) {
    try {
      await api.ruleDelete(id);
      await load();
    } catch (e) {
      console.error('Delete rule error:', e);
    }
  }

  async function handleToggle(rule: Rule) {
    try {
      await api.ruleEdit({ ...rule, enabled: !rule.enabled });
      await load();
    } catch (e) {
      console.error('Toggle rule error:', e);
    }
  }

  function handleDragStart(idx: number) { dragItem.current = idx; }
  function handleDragEnter(idx: number) { dragOver.current = idx; }

  async function handleDragEnd() {
    if (dragItem.current === null || dragOver.current === null) return;
    if (dragItem.current === dragOver.current) return;
    const reordered = [...rules];
    const [removed] = reordered.splice(dragItem.current, 1);
    reordered.splice(dragOver.current, 0, removed);
    setRules(reordered);
    dragItem.current = null;
    dragOver.current = null;
    try {
      await api.ruleReorder(reordered.map(r => r.id));
    } catch { await load(); }
  }

  function updateModal(field: string, value: unknown) {
    setModal(prev => ({
      ...prev,
      rule: prev.rule ? { ...prev.rule, [field]: value } : null,
    }));
  }

  function getProxyName(id: number | undefined) {
    if (id === undefined || id < 0) return '';
    return proxies.find(p => p.id === id)?.name || `Proxy #${id}`;
  }

  function getChainName(id: number | undefined) {
    if (id === undefined || id < 0) return '';
    return chains.find(c => c.id === id)?.name || `Chain #${id}`;
  }

  const filteredApps = systemApps.filter(a =>
    a.name.toLowerCase().includes(appSearch.toLowerCase()) ||
    a.exec.toLowerCase().includes(appSearch.toLowerCase())
  );

  return (
    <div>
      {/* Top bar */}
      <div className="mb-4 flex items-center gap-3">
        <button
          onClick={() => { setModal({ open: true, rule: { ...EMPTY_RULE } }); setAppSearch(''); }}
          className="rounded-md bg-[#6366f1] px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-[#818cf8]"
        >
          Add Rule
        </button>
      </div>

      {/* Rules table */}
      {rules.length === 0 ? (
        <div className="flex h-64 items-center justify-center text-[#64748b]">
          <div className="text-center">
            <p className="text-lg">No rules configured</p>
            <p className="mt-1 text-sm">Add a rule to control traffic routing</p>
          </div>
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-[#2d3348]">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#2d3348] bg-[#232733] text-left text-xs text-[#64748b]">
                <th className="px-4 py-2.5 font-medium">#</th>
                <th className="px-4 py-2.5 font-medium">Name</th>
                <th className="px-4 py-2.5 font-medium">Match</th>
                <th className="px-4 py-2.5 font-medium">Action</th>
                <th className="px-4 py-2.5 font-medium">Target</th>
                <th className="px-4 py-2.5 font-medium">Enabled</th>
                <th className="px-4 py-2.5 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule, idx) => (
                <tr
                  key={rule.id}
                  draggable
                  onDragStart={() => handleDragStart(idx)}
                  onDragEnter={() => handleDragEnter(idx)}
                  onDragEnd={handleDragEnd}
                  onDragOver={e => e.preventDefault()}
                  className="border-b border-[#2d3348] bg-[#1a1d27] transition-colors hover:bg-[#232733] cursor-grab active:cursor-grabbing"
                >
                  <td className="px-4 py-2.5 text-[#64748b]">{rule.priority}</td>
                  <td className="px-4 py-2.5 font-medium">{rule.name}</td>
                  <td className="px-4 py-2.5">
                    <div className="flex flex-wrap gap-1">
                      {rule.match_app && <span className={`rounded px-1.5 py-0.5 text-[10px] ${MATCH_BADGE.app}`}>App: {rule.match_app}</span>}
                      {rule.match_domain && <span className={`rounded px-1.5 py-0.5 text-[10px] ${MATCH_BADGE.domain}`}>Domain: {rule.match_domain}</span>}
                      {rule.match_ip && <span className={`rounded px-1.5 py-0.5 text-[10px] ${MATCH_BADGE.ip}`}>IP: {rule.match_ip}</span>}
                      {rule.match_port && <span className={`rounded px-1.5 py-0.5 text-[10px] ${MATCH_BADGE.port}`}>Port: {rule.match_port}</span>}
                      {!rule.match_app && !rule.match_domain && !rule.match_ip && !rule.match_port && (
                        <span className="text-[10px] text-[#64748b]">All traffic</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={`rounded px-2 py-0.5 text-[10px] font-semibold ${ACTION_COLORS[rule.action]}`}>{rule.action}</span>
                  </td>
                  <td className="px-4 py-2.5 text-[#64748b]">
                    {rule.action === 'PROXY' ? getProxyName(rule.proxy_id) : ''}
                    {rule.action === 'CHAIN' ? getChainName(rule.chain_id) : ''}
                  </td>
                  <td className="px-4 py-2.5">
                    <button
                      onClick={() => handleToggle(rule)}
                      className={`relative h-5 w-9 rounded-full transition-colors ${rule.enabled ? 'bg-[#6366f1]' : 'bg-[#2d3348]'}`}
                    >
                      <span className={`absolute top-0.5 left-0.5 h-4 w-4 rounded-full bg-white transition-transform ${rule.enabled ? 'translate-x-4' : 'translate-x-0'}`} />
                    </button>
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex gap-2">
                      <button onClick={() => { setModal({ open: true, rule: { ...rule } }); setAppSearch(''); }} className="text-xs text-[#64748b] hover:text-[#e2e8f0]">Edit</button>
                      <button onClick={() => handleDelete(rule.id)} className="text-xs text-[#ef4444] hover:text-[#f87171]">Delete</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Add/Edit modal */}
      {modal.open && modal.rule && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => { setShowAppPicker(false); setShowActionDd(false); setShowProxyDd(false); setShowChainDd(false); }}>
          <div className="w-full max-w-lg rounded-lg border border-[#2d3348] bg-[#1a1d27] p-6 shadow-2xl" onClick={e => e.stopPropagation()}>
            <h2 className="mb-4 text-lg font-semibold">
              {modal.rule.id ? 'Edit Rule' : 'Add Rule'}
            </h2>

            <div className="space-y-3">
              {/* Name + Priority */}
              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2">
                  <label className="mb-1 block text-xs text-[#64748b]">Name</label>
                  <input type="text" value={modal.rule.name || ''} onChange={e => updateModal('name', e.target.value)}
                    className="w-full rounded-md border border-[#2d3348] bg-[#232733] px-3 py-2 text-sm text-[#e2e8f0] outline-none focus:border-[#6366f1]" />
                </div>
                <div>
                  <label className="mb-1 block text-xs text-[#64748b]">Priority</label>
                  <input type="number" value={modal.rule.priority ?? 100} onChange={e => updateModal('priority', parseInt(e.target.value) || 0)}
                    className="w-full rounded-md border border-[#2d3348] bg-[#232733] px-3 py-2 text-sm text-[#e2e8f0] outline-none focus:border-[#6366f1]" />
                </div>
              </div>

              {/* Match App — with system app picker */}
              <div className="relative">
                <label className="mb-1 block text-xs text-[#64748b]">Match App</label>
                <div className="flex gap-2">
                  <input type="text" value={modal.rule.match_app || ''} onChange={e => updateModal('match_app', e.target.value)}
                    placeholder="e.g. firefox"
                    className="flex-1 rounded-md border border-[#2d3348] bg-[#232733] px-3 py-2 text-sm text-[#e2e8f0] placeholder-[#64748b] outline-none focus:border-[#6366f1]" />
                  <button type="button" onClick={() => { setShowAppPicker(p => !p); setAppSearch(''); }}
                    className="rounded-md border border-[#2d3348] bg-[#232733] px-3 py-2 text-xs text-[#64748b] hover:text-[#e2e8f0] hover:border-[#6366f1]"
                    title="Browse system apps">
                    Browse
                  </button>
                </div>
                {showAppPicker && (
                  <div className="absolute z-50 mt-1 w-full rounded-md border border-[#2d3348] bg-[#232733] shadow-xl">
                    <div className="border-b border-[#2d3348] p-2">
                      <input type="text" value={appSearch} onChange={e => setAppSearch(e.target.value)}
                        placeholder="Search apps..."
                        autoFocus
                        className="w-full rounded border border-[#2d3348] bg-[#1a1d27] px-2 py-1.5 text-sm text-[#e2e8f0] placeholder-[#64748b] outline-none focus:border-[#6366f1]" />
                    </div>
                    <div className="max-h-48 overflow-y-auto">
                      {filteredApps.length === 0 ? (
                        <div className="px-3 py-2 text-xs text-[#64748b]">No apps found</div>
                      ) : filteredApps.slice(0, 50).map((app, i) => (
                        <button key={i} type="button"
                          onClick={() => {
                            updateModal('match_app', app.exec);
                            if (!modal.rule?.name) updateModal('name', app.name);
                            setShowAppPicker(false);
                          }}
                          className="flex w-full items-center gap-3 px-3 py-2 text-left text-sm hover:bg-[#6366f1] hover:text-white transition-colors">
                          <div className="flex-1">
                            <div className="font-medium text-[#e2e8f0]">{app.name}</div>
                            <div className="text-[10px] text-[#64748b]">{app.exec}</div>
                          </div>
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Match Domains — multi-domain tag input */}
              <div>
                <label className="mb-1 block text-xs text-[#64748b]">Match Domains</label>
                <div className="rounded-md border border-[#2d3348] bg-[#232733] px-2 py-1.5 min-h-[38px] flex flex-wrap gap-1.5 items-center focus-within:border-[#6366f1]">
                  {(modal.rule.match_domain || '').split(',').filter(d => d.trim()).map((d, i) => (
                    <span key={i} className="inline-flex items-center gap-1 rounded bg-[#22c55e]/15 px-2 py-0.5 text-xs text-[#4ade80]">
                      {d.trim()}
                      <button type="button" onClick={() => {
                        const domains = (modal.rule?.match_domain || '').split(',').filter(x => x.trim());
                        domains.splice(i, 1);
                        updateModal('match_domain', domains.join(', '));
                      }} className="ml-0.5 text-[#4ade80]/60 hover:text-[#ef4444]">x</button>
                    </span>
                  ))}
                  <input
                    type="text"
                    placeholder={!(modal.rule.match_domain || '').trim() ? 'e.g. *.google.com — press Enter to add' : 'Add domain...'}
                    className="flex-1 min-w-[120px] bg-transparent text-sm text-[#e2e8f0] placeholder-[#64748b] outline-none"
                    onKeyDown={e => {
                      if (e.key === 'Enter' || e.key === ',') {
                        e.preventDefault();
                        const val = (e.target as HTMLInputElement).value.trim().replace(/,$/,'');
                        if (val) {
                          const existing = (modal.rule?.match_domain || '').split(',').filter(x => x.trim());
                          existing.push(val);
                          updateModal('match_domain', existing.join(', '));
                          (e.target as HTMLInputElement).value = '';
                        }
                      }
                    }}
                  />
                </div>
                <p className="mt-1 text-[10px] text-[#64748b]">Wildcards: *.google.com, *.ch, *streaming* — Enter per aggiungere</p>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="mb-1 block text-xs text-[#64748b]">Match IP</label>
                  <input type="text" value={modal.rule.match_ip || ''} onChange={e => updateModal('match_ip', e.target.value)}
                    placeholder="e.g. 10.0.0.0/8"
                    className="w-full rounded-md border border-[#2d3348] bg-[#232733] px-3 py-2 text-sm text-[#e2e8f0] placeholder-[#64748b] outline-none focus:border-[#6366f1]" />
                </div>
                <div>
                  <label className="mb-1 block text-xs text-[#64748b]">Match Port</label>
                  <input type="text" value={modal.rule.match_port || ''} onChange={e => updateModal('match_port', e.target.value)}
                    placeholder="e.g. 80,443"
                    className="w-full rounded-md border border-[#2d3348] bg-[#232733] px-3 py-2 text-sm text-[#e2e8f0] placeholder-[#64748b] outline-none focus:border-[#6366f1]" />
                </div>
              </div>

              {/* Action — custom dropdown */}
              <div className="relative">
                <label className="mb-1 block text-xs text-[#64748b]">Action</label>
                <button type="button" onClick={() => setShowActionDd(p => !p)}
                  className="flex w-full items-center justify-between rounded-md border border-[#2d3348] bg-[#232733] px-3 py-2 text-sm text-[#e2e8f0] outline-none focus:border-[#6366f1]">
                  <span className={`rounded px-2 py-0.5 text-xs font-semibold ${ACTION_COLORS[modal.rule.action || 'DIRECT']}`}>
                    {modal.rule.action || 'DIRECT'}
                  </span>
                  <svg className="h-4 w-4 text-[#64748b]" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z" clipRule="evenodd" />
                  </svg>
                </button>
                {showActionDd && (
                  <div className="absolute z-50 mt-1 w-full rounded-md border border-[#2d3348] bg-[#232733] py-1 shadow-xl">
                    {ACTIONS.map(a => (
                      <button key={a} type="button"
                        onClick={() => { updateModal('action', a); setShowActionDd(false); }}
                        className={`flex w-full items-center gap-2 px-3 py-2 text-left text-sm transition-colors hover:bg-[#6366f1] hover:text-white ${modal.rule?.action === a ? 'bg-[#6366f1]/20' : ''}`}>
                        <span className={`rounded px-2 py-0.5 text-[10px] font-semibold ${ACTION_COLORS[a]}`}>{a}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {/* Proxy selector — custom dropdown */}
              {modal.rule.action === 'PROXY' && (
                <div className="relative">
                  <label className="mb-1 block text-xs text-[#64748b]">Proxy</label>
                  <button type="button" onClick={() => setShowProxyDd(p => !p)}
                    className="flex w-full items-center justify-between rounded-md border border-[#2d3348] bg-[#232733] px-3 py-2 text-sm text-[#e2e8f0] outline-none focus:border-[#6366f1]">
                    <span>{modal.rule.proxy_id ? getProxyName(modal.rule.proxy_id) : 'Select proxy...'}</span>
                    <svg className="h-4 w-4 text-[#64748b]" viewBox="0 0 20 20" fill="currentColor">
                      <path fillRule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z" clipRule="evenodd" />
                    </svg>
                  </button>
                  {showProxyDd && (
                    <div className="absolute z-50 mt-1 w-full rounded-md border border-[#2d3348] bg-[#232733] py-1 shadow-xl">
                      {proxies.map(p => (
                        <button key={p.id} type="button"
                          onClick={() => { updateModal('proxy_id', p.id); setShowProxyDd(false); }}
                          className={`block w-full px-3 py-2 text-left text-sm transition-colors hover:bg-[#6366f1] hover:text-white ${modal.rule?.proxy_id === p.id ? 'bg-[#6366f1]/20 text-[#818cf8]' : 'text-[#e2e8f0]'}`}>
                          {p.name} <span className="text-[#64748b]">({p.host}:{p.port})</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Chain selector — custom dropdown */}
              {modal.rule.action === 'CHAIN' && (
                <div className="relative">
                  <label className="mb-1 block text-xs text-[#64748b]">Chain</label>
                  <button type="button" onClick={() => setShowChainDd(p => !p)}
                    className="flex w-full items-center justify-between rounded-md border border-[#2d3348] bg-[#232733] px-3 py-2 text-sm text-[#e2e8f0] outline-none focus:border-[#6366f1]">
                    <span>{modal.rule.chain_id ? getChainName(modal.rule.chain_id) : 'Select chain...'}</span>
                    <svg className="h-4 w-4 text-[#64748b]" viewBox="0 0 20 20" fill="currentColor">
                      <path fillRule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z" clipRule="evenodd" />
                    </svg>
                  </button>
                  {showChainDd && (
                    <div className="absolute z-50 mt-1 w-full rounded-md border border-[#2d3348] bg-[#232733] py-1 shadow-xl">
                      {chains.map(c => (
                        <button key={c.id} type="button"
                          onClick={() => { updateModal('chain_id', c.id); setShowChainDd(false); }}
                          className={`block w-full px-3 py-2 text-left text-sm transition-colors hover:bg-[#6366f1] hover:text-white ${modal.rule?.chain_id === c.id ? 'bg-[#6366f1]/20 text-[#818cf8]' : 'text-[#e2e8f0]'}`}>
                          {c.name}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="mt-6 flex justify-end gap-3">
              <button onClick={() => setModal({ open: false, rule: null })}
                className="rounded-md border border-[#2d3348] bg-[#232733] px-4 py-2 text-sm text-[#64748b] transition-colors hover:text-[#e2e8f0]">
                Cancel
              </button>
              <button onClick={handleSave} disabled={saving || !modal.rule.name}
                className="rounded-md bg-[#6366f1] px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-[#818cf8] disabled:opacity-50 disabled:cursor-not-allowed">
                {saving ? 'Saving...' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
