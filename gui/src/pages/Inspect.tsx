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
  content_type?: string;
  headers: Record<string, string>;
  body?: string;
  body_len?: number;
  body_decoded?: boolean;
  body_encoding_orig?: string;
  content_length?: number;
}

type CtypeFilter  = 'all' | 'json' | 'html' | 'xml' | 'text' | 'other';
type StatusFilter = 'all' | '2xx' | '3xx' | '4xx' | '5xx';

function ctypeMatches(entry_ct: string | undefined, filter: CtypeFilter): boolean {
  if (filter === 'all') return true;
  const ct = (entry_ct || '').toLowerCase();
  switch (filter) {
    case 'json':  return ct.includes('json');
    case 'html':  return ct.includes('html');
    case 'xml':   return ct.includes('xml');
    case 'text':  return ct.startsWith('text/') && !ct.includes('html');
    case 'other': return !ct.includes('json') && !ct.includes('html') &&
                         !ct.includes('xml')  && !ct.startsWith('text/');
  }
}

function statusMatches(status: number | undefined, filter: StatusFilter): boolean {
  if (filter === 'all' || !status) return filter === 'all';
  const s = Math.floor(status / 100);
  return filter === `${s}xx`;
}

interface InspectStatus {
  enabled: boolean;
  ca_installed: boolean;
  ca_cert_path: string;
  cached_certs: number;
  ring_count?: number;
  skipped_h2?: number;
  parse_failures?: number;
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
  const [ctypeFilter,  setCtypeFilter]  = useState<CtypeFilter>('all');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [ctypeOpen,    setCtypeOpen]    = useState(false);
  const [statusOpen,   setStatusOpen]   = useState(false);
  const [toggling, setToggling] = useState(false);
  const ctypeRef  = useRef<HTMLDivElement>(null);
  const statusRef = useRef<HTMLDivElement>(null);
  const seqRef = useRef(0);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const pollInFlight = useRef(false);   /* drop poll() calls while one is pending */
  const [detailLoading, setDetailLoading] = useState(false);

  /* Close dropdowns on outside click */
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ctypeRef.current  && !ctypeRef.current.contains(e.target as Node))  setCtypeOpen(false);
      if (statusRef.current && !statusRef.current.contains(e.target as Node)) setStatusOpen(false);
    }
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, []);

  const CTYPE_OPTIONS: { value: CtypeFilter; label: string }[] = [
    { value: 'all',   label: 'all types' },
    { value: 'json',  label: 'JSON' },
    { value: 'html',  label: 'HTML' },
    { value: 'xml',   label: 'XML' },
    { value: 'text',  label: 'text/*' },
    { value: 'other', label: 'other' },
  ];
  const STATUS_OPTIONS: { value: StatusFilter; label: string }[] = [
    { value: 'all', label: 'all status' },
    { value: '2xx', label: '2xx' },
    { value: '3xx', label: '3xx' },
    { value: '4xx', label: '4xx' },
    { value: '5xx', label: '5xx' },
  ];
  const ctypeLabel  = CTYPE_OPTIONS.find(o => o.value === ctypeFilter)!.label;
  const statusLabel = STATUS_OPTIONS.find(o => o.value === statusFilter)!.label;

  const loadStatus = useCallback(async () => {
    try {
      const raw = await api.inspectStatus();
      setStatus(raw);
    } catch { setStatus(null); }
  }, []);

  const poll = useCallback(async () => {
    /* Skip if a previous poll is still in-flight — prevents pile-up while
     * the daemon is busy serialising large payloads. */
    if (pollInFlight.current) return;
    /* Skip when the window is hidden — no point spending CPU + IPC round
     * trips when the user isn't looking. */
    if (typeof document !== 'undefined' && document.hidden) return;
    pollInFlight.current = true;
    try {
      /* Bounded by the daemon at 500 entries max per call → small payload. */
      const raw = await api.inspectList(seqRef.current, 500);
      if (Array.isArray(raw) && raw.length > 0) {
        /* Daemon-restart detection: if any returned seq is LESS than the GUI's
         * last seen, the daemon restarted (seq resets to 1). Wipe and rebuild. */
        const minSeq = Math.min(...raw.map((e: InspectEntry) => e.seq || 0));
        if (seqRef.current > 0 && minSeq < seqRef.current) {
          seqRef.current = 0;
          setEntries(raw);
          const maxSeq = Math.max(...raw.map((e: InspectEntry) => e.seq || 0));
          seqRef.current = maxSeq;
          return;
        }
        setEntries(prev => {
          const merged = [...prev, ...raw];
          /* Local cap below the daemon ring (5000) to keep React-tree cheap
           * and memory bounded at ~2-3 MB for summary rows. */
          if (merged.length > 2000) return merged.slice(-2000);
          return merged;
        });
        const maxSeq = Math.max(...raw.map((e: InspectEntry) => e.seq || 0));
        if (maxSeq > seqRef.current) seqRef.current = maxSeq;
      }
    } catch { /* daemon may not support it */ }
    finally { pollInFlight.current = false; }
  }, []);

  useEffect(() => {
    loadStatus();
    /* Only poll when capture is active — prevents hammering daemon IPC */
    if (status?.enabled) {
      poll();
      pollRef.current = setInterval(poll, 3000);
    }
    return () => { if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; } };
  }, [loadStatus, poll, status?.enabled]);

  /* Resume polling when the window becomes visible again. */
  useEffect(() => {
    function onVis() { if (!document.hidden) poll(); }
    document.addEventListener('visibilitychange', onVis);
    return () => document.removeEventListener('visibilitychange', onVis);
  }, [poll]);

  /* Click a row → load full entry (headers + body) on demand. */
  const handleSelect = useCallback(async (e: InspectEntry) => {
    setSelected(e);
    setDetailLoading(true);
    try {
      const full = await api.inspectGet(e.seq);
      if (full) setSelected(full as InspectEntry);
    } catch { /* keep the summary */ }
    finally { setDetailLoading(false); }
  }, []);

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

  /* Index responses by request key so we can both:
   *   (a) show response status/size on each request row
   *   (b) apply content-type / status filters against the *paired* response
   * Key = `${domain}|${dst_port}|${ts_bucket}` (5s bucket for proximity) */
  const respIndex = new Map<string, InspectEntry>();
  for (const e of entries) {
    if (e.is_request) continue;
    const bucket = Math.floor(e.ts / 5);
    respIndex.set(`${e.domain}|${e.dst_port}|${bucket}`,   e);
    respIndex.set(`${e.domain}|${e.dst_port}|${bucket-1}`, e);
  }
  const pairResp = (req: InspectEntry): InspectEntry | undefined => {
    const bucket = Math.floor(req.ts / 5);
    return respIndex.get(`${req.domain}|${req.dst_port}|${bucket}`) ??
           respIndex.get(`${req.domain}|${req.dst_port}|${bucket+1}`);
  };

  const textFiltered = filter
    ? entries.filter(e => {
        const f = filter.toLowerCase();
        return (e.domain || '').toLowerCase().includes(f) ||
               (e.url || '').toLowerCase().includes(f) ||
               (e.method || '').toLowerCase().includes(f) ||
               String(e.status || '').includes(f);
      })
    : entries;

  /* Request rows, filtered by content-type + status through their paired
   * response. A request without a matching response is kept if status=all. */
  const requests = textFiltered.filter(e => {
    if (!e.is_request) return false;
    if (ctypeFilter === 'all' && statusFilter === 'all') return true;
    const resp = pairResp(e);
    if (!resp) return statusFilter === 'all' && ctypeFilter === 'all';
    return ctypeMatches(resp.content_type, ctypeFilter) &&
           statusMatches(resp.status, statusFilter);
  });

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

        {/* Content-Type custom dropdown */}
        <div className="relative" ref={ctypeRef}>
          <button
            onClick={() => { setCtypeOpen(v => !v); setStatusOpen(false); }}
            title="Filter by response Content-Type"
            className="flex items-center gap-2 rounded-md border border-[#2d3348] bg-[#232733] px-3 py-1.5 text-xs text-[#e2e8f0] transition-colors hover:border-[#6366f1]"
          >
            <span>{ctypeLabel}</span>
            <svg className="h-3 w-3 text-[#64748b]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          {ctypeOpen && (
            <div className="absolute left-0 z-50 mt-1 min-w-[140px] rounded-md border border-[#2d3348] bg-[#1a1d27] py-1 shadow-lg">
              {CTYPE_OPTIONS.map(opt => (
                <button
                  key={opt.value}
                  onClick={() => { setCtypeFilter(opt.value); setCtypeOpen(false); }}
                  className={`flex w-full items-center px-3 py-1.5 text-left text-xs transition-colors hover:bg-[#2d3348] ${
                    ctypeFilter === opt.value ? 'text-[#6366f1]' : 'text-[#e2e8f0]'
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Status class custom dropdown */}
        <div className="relative" ref={statusRef}>
          <button
            onClick={() => { setStatusOpen(v => !v); setCtypeOpen(false); }}
            title="Filter by HTTP status class"
            className="flex items-center gap-2 rounded-md border border-[#2d3348] bg-[#232733] px-3 py-1.5 text-xs text-[#e2e8f0] transition-colors hover:border-[#6366f1]"
          >
            <span>{statusLabel}</span>
            <svg className="h-3 w-3 text-[#64748b]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          {statusOpen && (
            <div className="absolute left-0 z-50 mt-1 min-w-[120px] rounded-md border border-[#2d3348] bg-[#1a1d27] py-1 shadow-lg">
              {STATUS_OPTIONS.map(opt => (
                <button
                  key={opt.value}
                  onClick={() => { setStatusFilter(opt.value); setStatusOpen(false); }}
                  className={`flex w-full items-center px-3 py-1.5 text-left text-xs transition-colors hover:bg-[#2d3348] ${
                    statusFilter === opt.value ? 'text-[#6366f1]' : 'text-[#e2e8f0]'
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          )}
        </div>

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
          {!!status?.skipped_h2 && (
            <span className="text-[#f59e0b]" title="HTTP/2 traffic skipped — native h2 parsing not yet implemented. Make sure QUIC block is on and server accepts ALPN http/1.1.">
              h2 skipped: {status.skipped_h2}
            </span>
          )}
          {!!status?.parse_failures && (
            <span className="text-[#94a3b8]" title="Bytes received but not parseable as HTTP/1.1 — h2 frames, partial TCP segments, or non-HTTP protocols.">
              parse-fail: {status.parse_failures}
            </span>
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
                const resp = pairResp(e);
                return (
                  <tr
                    key={e.seq}
                    onClick={() => handleSelect(e)}
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
              <h3 className="text-sm font-semibold">
                Request Details
                {detailLoading && <span className="ml-2 text-[10px] text-[#64748b]">loading…</span>}
              </h3>
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
                <h4 className="mb-1 flex items-center justify-between text-xs font-semibold text-[#64748b]">
                  <span>Body ({selected.body_len || 0} bytes)</span>
                  {selected.body_encoding_orig && (
                    <span className={`text-[10px] ${selected.body_decoded ? 'text-[#22c55e]' : 'text-[#f59e0b]'}`}>
                      {selected.body_decoded
                        ? `decoded from ${selected.body_encoding_orig}`
                        : `${selected.body_encoding_orig} (raw — decode failed)`}
                    </span>
                  )}
                </h4>
                <pre className="max-h-72 overflow-auto rounded bg-[#232733] p-2 text-[10px] text-[#e2e8f0] whitespace-pre-wrap break-all">
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
