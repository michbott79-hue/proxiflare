import { useState, useEffect, useCallback, useRef } from 'react';
import * as api from '../lib/api';

interface InspectEntry {
  seq: number;
  ts: number;
  domain: string;
  dst_ip: string;
  dst_port: number;
  is_request: boolean;
  tls: boolean;
  method?: string;
  url?: string;
  version?: string;
  status?: number;
  status_text?: string;
  headers: Record<string, string>;
  body?: string;
  body_len?: number;
  content_length?: number;
}

interface InspectStatus {
  enabled: boolean;
  ca_installed: boolean;
  ca_cert_path: string;
  cached_certs: number;
}

const METHOD_COLORS: Record<string, string> = {
  GET: 'text-[#22c55e]',
  POST: 'text-[#6366f1]',
  PUT: 'text-[#f59e0b]',
  DELETE: 'text-[#ef4444]',
  PATCH: 'text-[#a855f7]',
  HEAD: 'text-[#64748b]',
  OPTIONS: 'text-[#06b6d4]',
};

function statusColor(code: number): string {
  if (code >= 200 && code < 300) return 'text-[#22c55e]';
  if (code >= 300 && code < 400) return 'text-[#f59e0b]';
  if (code >= 400 && code < 500) return 'text-[#ef4444]';
  if (code >= 500) return 'text-[#dc2626]';
  return 'text-[#64748b]';
}

export default function Inspect() {
  const [entries, setEntries] = useState<InspectEntry[]>([]);
  const [status, setStatus] = useState<InspectStatus | null>(null);
  const [selected, setSelected] = useState<InspectEntry | null>(null);
  const [filter, setFilter] = useState('');
  const [toggling, setToggling] = useState(false);
  const seqRef = useRef(0);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadStatus = useCallback(async () => {
    try {
      const raw = await api.inspectStatus();
      setStatus(raw);
    } catch { setStatus(null); }
  }, []);

  const poll = useCallback(async () => {
    try {
      const raw = await api.inspectList(seqRef.current);
      if (Array.isArray(raw) && raw.length > 0) {
        setEntries(prev => {
          const merged = [...prev, ...raw];
          if (merged.length > 500) return merged.slice(-500);
          return merged;
        });
        const maxSeq = Math.max(...raw.map((e: InspectEntry) => e.seq || 0));
        if (maxSeq > seqRef.current) seqRef.current = maxSeq;
      }
    } catch { /* daemon may not support it */ }
  }, []);

  useEffect(() => {
    loadStatus();
    poll();
    pollRef.current = setInterval(poll, 500);
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [loadStatus, poll]);

  async function handleToggle() {
    setToggling(true);
    try {
      if (status?.enabled) {
        await api.inspectDisable();
      } else {
        await api.inspectEnable();
      }
      await loadStatus();
    } catch (e) { console.error('Inspect toggle error:', e); }
    finally { setToggling(false); }
  }

  async function handleGenerateCa() {
    try {
      await api.inspectGenerateCa();
      await loadStatus();
    } catch (e) { console.error('CA generation error:', e); }
  }

  const filtered = filter
    ? entries.filter(e => {
        const f = filter.toLowerCase();
        return (e.domain || '').toLowerCase().includes(f) ||
               (e.url || '').toLowerCase().includes(f) ||
               (e.method || '').toLowerCase().includes(f) ||
               String(e.status || '').includes(f);
      })
    : entries;

  /* Pair requests/responses by domain+port+time proximity */
  const requests = filtered.filter(e => e.is_request);

  return (
    <div className="flex h-full flex-col gap-3">
      {/* Toolbar */}
      <div className="flex items-center gap-3">
        <button
          onClick={handleToggle}
          disabled={toggling || (!status?.ca_installed && !status?.enabled)}
          className={`rounded-md px-4 py-2 text-sm font-medium transition-colors ${
            status?.enabled
              ? 'bg-[#ef4444] text-white hover:bg-[#dc2626]'
              : 'bg-[#6366f1] text-white hover:bg-[#818cf8]'
          } disabled:opacity-50`}
        >
          {status?.enabled ? 'Stop Capture' : 'Start Capture'}
        </button>

        {!status?.ca_installed && (
          <button
            onClick={handleGenerateCa}
            className="rounded-md border border-[#f59e0b]/30 px-4 py-2 text-sm text-[#f59e0b] hover:bg-[#f59e0b]/10"
          >
            Generate CA Certificate
          </button>
        )}

        <input
          type="text"
          value={filter}
          onChange={e => setFilter(e.target.value)}
          placeholder="Filter by domain, URL, method..."
          className="w-64 rounded-md border border-[#2d3348] bg-[#232733] px-3 py-1.5 text-xs text-[#e2e8f0] placeholder-[#64748b] outline-none focus:border-[#6366f1]"
        />

        <button
          onClick={() => { setEntries([]); seqRef.current = 0; }}
          className="rounded-md border border-[#2d3348] px-3 py-1.5 text-xs text-[#64748b] hover:text-[#e2e8f0]"
        >
          Clear
        </button>

        <div className="ml-auto flex items-center gap-3 text-xs text-[#64748b]">
          {status?.ca_installed && (
            <span className="flex items-center gap-1.5">
              <span className="inline-block h-2 w-2 rounded-full bg-[#22c55e]" />
              CA ready
            </span>
          )}
          {status?.enabled && (
            <span className="flex items-center gap-1.5">
              <span className="inline-block h-2 w-2 rounded-full bg-[#ef4444] animate-pulse" />
              Capturing
            </span>
          )}
          <span>{entries.length} entries</span>
          {status?.cached_certs !== undefined && (
            <span>{status.cached_certs} cached certs</span>
          )}
        </div>
      </div>

      {/* Main content: table + detail panel */}
      <div className="flex flex-1 gap-3 overflow-hidden">
        {/* Request table */}
        <div className="flex-1 overflow-auto rounded-lg border border-[#2d3348]">
          <table className="w-full text-xs">
            <thead className="sticky top-0 z-10">
              <tr className="border-b border-[#2d3348] bg-[#232733] text-left text-[#64748b]">
                <th className="px-3 py-2 font-medium w-10">#</th>
                <th className="px-3 py-2 font-medium w-16">Method</th>
                <th className="px-3 py-2 font-medium">URL / Domain</th>
                <th className="px-3 py-2 font-medium w-14">Status</th>
                <th className="px-3 py-2 font-medium w-16">Size</th>
                <th className="px-3 py-2 font-medium w-10">TLS</th>
              </tr>
            </thead>
            <tbody>
              {requests.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-3 py-12 text-center text-[#64748b]">
                    {status?.enabled
                      ? 'Waiting for traffic...'
                      : 'Click "Start Capture" to begin intercepting HTTP traffic'}
                  </td>
                </tr>
              ) : requests.map((e) => {
                /* Find matching response */
                const resp = filtered.find(r =>
                  !r.is_request &&
                  r.domain === e.domain &&
                  r.dst_port === e.dst_port &&
                  Math.abs(r.ts - e.ts) < 5
                );
                return (
                  <tr
                    key={e.seq}
                    onClick={() => setSelected(e)}
                    className={`border-b border-[#2d3348] cursor-pointer transition-colors hover:bg-[#232733] ${
                      selected?.seq === e.seq ? 'bg-[#6366f1]/10' : 'bg-[#1a1d27]'
                    }`}
                  >
                    <td className="px-3 py-1.5 text-[#64748b]">{e.seq}</td>
                    <td className={`px-3 py-1.5 font-semibold ${METHOD_COLORS[e.method || ''] || 'text-[#e2e8f0]'}`}>
                      {e.method}
                    </td>
                    <td className="px-3 py-1.5 truncate max-w-[400px]">
                      <span className="text-[#e2e8f0]">{e.url || e.domain}</span>
                      {e.domain && e.url && (
                        <span className="ml-2 text-[#64748b]">{e.domain}</span>
                      )}
                    </td>
                    <td className={`px-3 py-1.5 font-semibold ${resp ? statusColor(resp.status || 0) : 'text-[#64748b]'}`}>
                      {resp?.status || '...'}
                    </td>
                    <td className="px-3 py-1.5 text-[#64748b]">
                      {resp?.content_length ? `${Math.round(resp.content_length / 1024)}KB` : '-'}
                    </td>
                    <td className="px-3 py-1.5">
                      {e.tls ? (
                        <span className="text-[#22c55e]">🔒</span>
                      ) : (
                        <span className="text-[#64748b]">—</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Detail panel */}
        {selected && (
          <div className="w-[400px] shrink-0 overflow-auto rounded-lg border border-[#2d3348] bg-[#1a1d27] p-4">
            <div className="mb-3 flex items-center justify-between">
              <h3 className="text-sm font-semibold">Request Details</h3>
              <button
                onClick={() => setSelected(null)}
                className="text-xs text-[#64748b] hover:text-[#e2e8f0]"
              >
                Close
              </button>
            </div>

            {/* Request line */}
            <div className="mb-3 rounded bg-[#232733] p-2 text-xs">
              <span className={`font-semibold ${METHOD_COLORS[selected.method || ''] || ''}`}>
                {selected.method}
              </span>{' '}
              <span className="text-[#e2e8f0] break-all">{selected.url}</span>{' '}
              <span className="text-[#64748b]">{selected.version}</span>
            </div>

            {/* Headers */}
            <div className="mb-3">
              <h4 className="mb-1 text-xs font-semibold text-[#64748b]">Headers</h4>
              <div className="space-y-0.5">
                {Object.entries(selected.headers || {}).map(([k, v]) => (
                  <div key={k} className="text-[10px]">
                    <span className="text-[#6366f1]">{k}</span>
                    <span className="text-[#64748b]">: </span>
                    <span className="text-[#e2e8f0] break-all">{v}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Body */}
            {selected.body && (
              <div>
                <h4 className="mb-1 text-xs font-semibold text-[#64748b]">
                  Body ({selected.body_len || 0} bytes)
                </h4>
                <pre className="max-h-48 overflow-auto rounded bg-[#232733] p-2 text-[10px] text-[#e2e8f0] whitespace-pre-wrap break-all">
                  {(() => {
                    try { return JSON.stringify(JSON.parse(selected.body), null, 2); }
                    catch { return selected.body; }
                  })()}
                </pre>
              </div>
            )}

            {/* Connection info */}
            <div className="mt-3 border-t border-[#2d3348] pt-3">
              <h4 className="mb-1 text-xs font-semibold text-[#64748b]">Connection</h4>
              <div className="space-y-0.5 text-[10px]">
                <div><span className="text-[#64748b]">Domain: </span><span className="text-[#e2e8f0]">{selected.domain}</span></div>
                <div><span className="text-[#64748b]">IP: </span><span className="text-[#e2e8f0]">{selected.dst_ip}:{selected.dst_port}</span></div>
                <div><span className="text-[#64748b]">TLS: </span><span className="text-[#e2e8f0]">{selected.tls ? 'Yes' : 'No'}</span></div>
                <div><span className="text-[#64748b]">Time: </span><span className="text-[#e2e8f0]">{new Date(selected.ts * 1000).toLocaleTimeString()}</span></div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
