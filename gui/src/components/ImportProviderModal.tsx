import { useEffect, useState } from 'react';
import { providersList, providersImport, type ProviderInfo, type ImportResult } from '../lib/api';

interface Props {
  onClose: () => void;
  onDone: () => void; /* parent reloads its proxy list */
}

/**
 * Modal: fetch provider list from the Tauri backend, let the user enter
 * API credentials, call `providers_import`, and render a result summary.
 *
 * Credentials are kept only in this component's React state — they never
 * hit localStorage or any persistence layer. This is intentional: API
 * secrets should not be stored in the frontend bundle. Future improvement
 * could move storage to the daemon's encrypted config.
 */
export default function ImportProviderModal({ onClose, onDone }: Props) {
  const [providers, setProviders] = useState<ProviderInfo[]>([]);
  const [providerId, setProviderId] = useState<string>('');
  const [apiKey, setApiKey] = useState('');
  const [apiSecret, setApiSecret] = useState('');
  const [showSecret, setShowSecret] = useState(false);
  const [importing, setImporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ImportResult | null>(null);

  useEffect(() => {
    providersList()
      .then(list => {
        setProviders(list);
        if (list.length > 0) setProviderId(list[0].id);
      })
      .catch(e => setError(String(e)));
  }, []);

  async function handleImport() {
    setImporting(true);
    setError(null);
    setResult(null);
    try {
      const r = await providersImport(providerId, apiKey.trim(), apiSecret.trim());
      setResult(r);
      if (r.added > 0) onDone(); /* parent refreshes its list */
    } catch (e) {
      setError(typeof e === 'string' ? e : (e instanceof Error ? e.message : JSON.stringify(e)));
    } finally {
      setImporting(false);
    }
  }

  const disabled = importing || !providerId || !apiKey.trim() || !apiSecret.trim();

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-lg rounded-xl border border-[#2d3348] bg-[#171a23] p-6 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-[#e2e8f0]">Import proxies from provider</h2>
          <button onClick={onClose} className="text-[#64748b] hover:text-[#e2e8f0]">✕</button>
        </div>

        {result ? (
          <div className="space-y-3">
            <div className="rounded-md border border-[#2d3348] bg-[#0f1117] p-4">
              <div className="grid grid-cols-4 gap-2 text-center">
                <Stat label="Fetched" value={result.fetched} color="text-[#94a3b8]" />
                <Stat label="Added" value={result.added} color="text-[#4ade80]" />
                <Stat label="Skipped" value={result.skipped} color="text-[#64748b]" />
                <Stat label="Failed" value={result.failed} color="text-[#f87171]" />
              </div>
            </div>
            {result.errors.length > 0 && (
              <div className="rounded-md border border-[#f87171]/30 bg-[#f87171]/5 p-3 text-xs text-[#f87171]">
                <p className="mb-1 font-semibold">Errors:</p>
                <ul className="ml-4 list-disc space-y-0.5">
                  {result.errors.slice(0, 6).map((e, i) => <li key={i}>{e}</li>)}
                  {result.errors.length > 6 && <li className="text-[#64748b]">…and {result.errors.length - 6} more</li>}
                </ul>
              </div>
            )}
            <div className="flex justify-end gap-2">
              <button onClick={() => setResult(null)} className="rounded-md border border-[#2d3348] bg-[#232733] px-4 py-2 text-sm text-[#94a3b8] hover:text-[#e2e8f0]">
                Import more
              </button>
              <button onClick={onClose} className="rounded-md bg-[#6366f1] px-4 py-2 text-sm font-medium text-white hover:bg-[#818cf8]">
                Done
              </button>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <div>
              <label className="mb-1 block text-xs uppercase tracking-wide text-[#64748b]">Provider</label>
              <select
                value={providerId}
                onChange={e => setProviderId(e.target.value)}
                className="w-full rounded-md border border-[#2d3348] bg-[#0f1117] px-3 py-2 text-sm text-[#e2e8f0] outline-none focus:border-[#6366f1]"
              >
                {providers.map(p => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="mb-1 block text-xs uppercase tracking-wide text-[#64748b]">API Key</label>
              <input
                type="text"
                value={apiKey}
                onChange={e => setApiKey(e.target.value)}
                placeholder="019b26f7-…"
                className="w-full rounded-md border border-[#2d3348] bg-[#0f1117] px-3 py-2 font-mono text-sm text-[#e2e8f0] outline-none focus:border-[#6366f1]"
              />
            </div>

            <div>
              <label className="mb-1 block text-xs uppercase tracking-wide text-[#64748b]">API Secret</label>
              <div className="relative">
                <input
                  type={showSecret ? 'text' : 'password'}
                  value={apiSecret}
                  onChange={e => setApiSecret(e.target.value)}
                  placeholder="••••••••"
                  className="w-full rounded-md border border-[#2d3348] bg-[#0f1117] px-3 py-2 pr-16 font-mono text-sm text-[#e2e8f0] outline-none focus:border-[#6366f1]"
                />
                <button
                  type="button"
                  onClick={() => setShowSecret(v => !v)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 rounded px-2 py-0.5 text-xs text-[#64748b] hover:text-[#e2e8f0]"
                >
                  {showSecret ? 'hide' : 'show'}
                </button>
              </div>
            </div>

            {error && (
              <div className="rounded-md border border-[#f87171]/30 bg-[#f87171]/5 p-3 text-xs text-[#f87171]">
                {error}
              </div>
            )}

            <p className="text-[11px] text-[#64748b]">
              Credentials are sent to the provider API directly and never stored. Existing proxies
              with the same host:port are skipped.
            </p>

            <div className="flex justify-end gap-2">
              <button onClick={onClose} className="rounded-md border border-[#2d3348] bg-[#232733] px-4 py-2 text-sm text-[#94a3b8] hover:text-[#e2e8f0]">
                Cancel
              </button>
              <button
                onClick={handleImport}
                disabled={disabled}
                className="rounded-md bg-[#6366f1] px-4 py-2 text-sm font-medium text-white hover:bg-[#818cf8] disabled:cursor-not-allowed disabled:opacity-50"
              >
                {importing ? 'Importing…' : 'Fetch & import'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div>
      <div className={`text-2xl font-bold tabular-nums ${color}`}>{value}</div>
      <div className="text-[10px] uppercase tracking-wider text-[#64748b]">{label}</div>
    </div>
  );
}
