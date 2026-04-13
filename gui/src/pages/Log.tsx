import { useEffect, useRef, useState, useCallback, useMemo } from 'react';
import type { RuleAction } from '../lib/types';
import { useLog } from '../hooks/useLog';

const ACTION_COLORS: Record<RuleAction, string> = {
  DIRECT: 'text-[#64748b]',
  PROXY:  'text-[#93c5fd]',
  CHAIN:  'text-[#c084fc]',
  BLOCK:  'text-[#f87171]',
  REJECT: 'text-[#fbbf24]',
};

const FILTER_ACTIONS: (RuleAction | 'ALL')[] = ['ALL', 'DIRECT', 'PROXY', 'CHAIN', 'BLOCK', 'REJECT'];
const ROW_HEIGHT = 22;
const OVERSCAN = 16;

function formatTime(ts: number): string {
  const d = new Date(ts * 1000);
  const h = String(d.getHours()).padStart(2, '0');
  const m = String(d.getMinutes()).padStart(2, '0');
  const s = String(d.getSeconds()).padStart(2, '0');
  return `${h}:${m}:${s}`;
}

function formatBytes(bytes: number): string {
  if (!bytes) return '';
  if (bytes < 1024) return `${bytes}`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}k`;
  return `${(bytes / (1024 * 1024)).toFixed(1)}M`;
}

function appLabel(path: string | undefined, ruleName: string | undefined): string {
  if (path && path.length) return path.split('/').pop() || path;
  if (ruleName && ruleName.length) return ruleName;
  return '—';
}

export default function Log() {
  const { entries, paused, dropped, toggle, clear } = useLog();
  const [filterApp, setFilterApp] = useState('');
  const [filterDomain, setFilterDomain] = useState('');
  const [filterAction, setFilterAction] = useState<RuleAction | 'ALL'>('ALL');
  const [showActionDd, setShowActionDd] = useState(false);
  const [search, setSearch] = useState('');
  const [searchDebounced, setSearchDebounced] = useState('');
  const scrollRef = useRef<HTMLDivElement>(null);
  const stickBottomRef = useRef(true);
  const [scrollTop, setScrollTop] = useState(0);
  const [containerHeight, setContainerHeight] = useState(600);

  /* Debounce search — typing shouldn't force a filter recomputation per keystroke */
  useEffect(() => {
    const t = setTimeout(() => setSearchDebounced(search), 120);
    return () => clearTimeout(t);
  }, [search]);

  /* Memoize filter: only recompute when inputs or entries change, NOT on scroll */
  const filtered = useMemo(() => {
    const needle = searchDebounced.toLowerCase();
    const app = filterApp.toLowerCase();
    const dom = filterDomain.toLowerCase();
    return entries.filter(e => {
      if (app && !(e.app || '').toLowerCase().includes(app)) return false;
      if (dom && !(e.domain || '').toLowerCase().includes(dom)) return false;
      if (filterAction !== 'ALL' && e.action !== filterAction) return false;
      if (needle) {
        const line = `${e.app} ${e.domain} ${e.dst_ip} ${e.proxy} ${e.rule}`.toLowerCase();
        if (!line.includes(needle)) return false;
      }
      return true;
    });
  }, [entries, filterApp, filterDomain, filterAction, searchDebounced]);

  const totalHeight = filtered.length * ROW_HEIGHT;
  const startIdx = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const endIdx = Math.min(filtered.length, Math.ceil((scrollTop + containerHeight) / ROW_HEIGHT) + OVERSCAN);
  const visible = filtered.slice(startIdx, endIdx);
  const offsetY = startIdx * ROW_HEIGHT;

  const handleScroll = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    setScrollTop(el.scrollTop);
    /* Stick-to-bottom only when user is at bottom. If they scroll up to
     * inspect history, don't yank them back when new entries arrive. */
    stickBottomRef.current = el.scrollHeight - el.clientHeight - el.scrollTop < 40;
  }, []);

  useEffect(() => {
    if (!paused && stickBottomRef.current && scrollRef.current) {
      /* rAF so the scroll happens after layout, avoids flash */
      requestAnimationFrame(() => {
        if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
      });
    }
  }, [filtered.length, paused]);

  useEffect(() => {
    if (scrollRef.current) {
      const ro = new ResizeObserver(([e]) => setContainerHeight(e.contentRect.height));
      ro.observe(scrollRef.current);
      return () => ro.disconnect();
    }
  }, []);

  return (
    <div className="flex h-full flex-col">
      <div className="mb-2 flex flex-wrap items-center gap-1.5">
        <input type="text" value={filterApp} onChange={e => setFilterApp(e.target.value)}
          placeholder="App"
          className="w-24 rounded border border-[#2d3348] bg-[#171a23] px-2 py-1 text-xs text-[#e2e8f0] placeholder-[#475569] outline-none focus:border-[#6366f1]" />
        <input type="text" value={filterDomain} onChange={e => setFilterDomain(e.target.value)}
          placeholder="Domain"
          className="w-32 rounded border border-[#2d3348] bg-[#171a23] px-2 py-1 text-xs text-[#e2e8f0] placeholder-[#475569] outline-none focus:border-[#6366f1]" />
        <div className="relative">
          <button type="button" onClick={() => setShowActionDd(p => !p)}
            className="flex w-24 items-center justify-between rounded border border-[#2d3348] bg-[#171a23] px-2 py-1 text-xs text-[#e2e8f0] hover:border-[#3d4358]">
            <span className={filterAction === 'ALL' ? 'text-[#94a3b8]' : ACTION_COLORS[filterAction as RuleAction]}>{filterAction}</span>
            <svg className="h-3 w-3 text-[#64748b]" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z" clipRule="evenodd" />
            </svg>
          </button>
          {showActionDd && (
            <div className="absolute z-50 mt-1 w-24 rounded border border-[#2d3348] bg-[#171a23] py-0.5 shadow-xl">
              {FILTER_ACTIONS.map(a => (
                <button key={a} type="button"
                  onClick={() => { setFilterAction(a); setShowActionDd(false); }}
                  className={`block w-full px-2 py-1 text-left text-xs hover:bg-[#6366f1] hover:text-white transition-colors ${
                    filterAction === a ? 'bg-[#232733]' : ''
                  } ${a === 'ALL' ? 'text-[#94a3b8]' : ACTION_COLORS[a as RuleAction]}`}>
                  {a}
                </button>
              ))}
            </div>
          )}
        </div>
        <input type="text" value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Search…"
          className="w-40 rounded border border-[#2d3348] bg-[#171a23] px-2 py-1 text-xs text-[#e2e8f0] placeholder-[#475569] outline-none focus:border-[#6366f1]" />

        <div className="ml-auto flex items-center gap-2">
          <span className="text-[11px] text-[#64748b] tabular-nums">
            {filtered.length.toLocaleString()}
            {filtered.length !== entries.length ? ` / ${entries.length.toLocaleString()}` : ''}
            {dropped > 0 ? <span className="ml-1 text-[#f59e0b]" title="Entries lost in ring buffer before GUI polled">↯{dropped}</span> : null}
          </span>
          <button onClick={toggle}
            className={`rounded border px-2.5 py-1 text-xs transition-colors ${paused
              ? 'border-[#f59e0b]/40 text-[#f59e0b] hover:bg-[#f59e0b]/10'
              : 'border-[#2d3348] bg-[#171a23] text-[#94a3b8] hover:text-[#e2e8f0]'}`}>
            {paused ? '▶ Resume' : '⏸ Pause'}
          </button>
          <button onClick={clear}
            className="rounded border border-[#2d3348] bg-[#171a23] px-2.5 py-1 text-xs text-[#94a3b8] transition-colors hover:text-[#e2e8f0]">
            Clear
          </button>
        </div>
      </div>

      {/* Column header */}
      <div className="flex items-center border-x border-t border-[#2d3348] bg-[#13161f] px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-[#475569]">
        <span className="w-[70px] shrink-0">Time</span>
        <span className="w-[14px] shrink-0"></span>
        <span className="w-[110px] shrink-0">App</span>
        <span className="w-[14px] shrink-0"></span>
        <span className="flex-1 min-w-0">Destination</span>
        <span className="w-[30px] shrink-0 mx-1">via</span>
        <span className="w-[140px] shrink-0">Proxy</span>
        <span className="w-[70px] shrink-0 text-right">Bytes</span>
      </div>

      <div
        ref={scrollRef}
        onScroll={handleScroll}
        className="flex-1 overflow-auto rounded-b-lg border border-[#2d3348] bg-[#0b0d13] font-mono text-xs"
        style={{ scrollbarGutter: 'stable' }}
      >
        {filtered.length === 0 ? (
          <div className="flex h-full items-center justify-center text-[#475569]">
            <div className="text-center">
              <p className="text-sm">No traffic</p>
              <p className="mt-1 text-[10px]">Entries will appear when matched processes connect</p>
            </div>
          </div>
        ) : (
          <div style={{ height: totalHeight, position: 'relative' }}>
            <div style={{ transform: `translateY(${offsetY}px)` }}>
              {visible.map((e, i) => {
                const actionColor = ACTION_COLORS[e.action as RuleAction] ?? 'text-[#94a3b8]';
                const zebra = (startIdx + i) % 2 === 0 ? 'bg-[#0b0d13]' : 'bg-[#0e1118]';
                const isDirect = e.action === 'DIRECT';
                return (
                  <div
                    key={e.seq || `${e.ts}-${startIdx + i}`}
                    style={{ height: ROW_HEIGHT }}
                    className={`flex items-center px-2 border-l-2 ${
                      isDirect ? 'border-l-transparent' : 'border-l-[#6366f1]/50'
                    } ${zebra} hover:bg-[#1a1d27] transition-colors`}
                  >
                    <span className="w-[70px] shrink-0 text-[#475569] tabular-nums">{formatTime(e.ts)}</span>
                    <span className={`w-[14px] shrink-0 ${e.success ? 'text-[#4ade80]' : 'text-[#f87171]'}`}>
                      {e.success ? '✓' : '✗'}
                    </span>
                    <span className="w-[110px] shrink-0 truncate text-[#fbbf24]" title={e.app}>
                      {appLabel(e.app, e.rule)}
                    </span>
                    <span className="w-[14px] shrink-0 text-[#475569]">›</span>
                    <span className="flex-1 min-w-0 truncate text-[#e2e8f0]" title={`${e.domain || e.dst_ip}:${e.dst_port}`}>
                      <span className="text-[#cbd5e1]">{e.domain || e.dst_ip}</span>
                      <span className="text-[#475569]">:{e.dst_port}</span>
                    </span>
                    <span className="w-[30px] shrink-0 mx-1 text-[#475569]">via</span>
                    <span className={`w-[140px] shrink-0 truncate font-semibold ${actionColor}`} title={e.proxy}>
                      {isDirect ? 'direct' : (e.proxy || `#${e.proxy_id}`)}
                    </span>
                    <span className="w-[70px] shrink-0 text-right text-[#475569] tabular-nums text-[10px]">
                      {e.bytes_tx || e.bytes_rx
                        ? `${formatBytes(e.bytes_tx)}↑${formatBytes(e.bytes_rx)}↓`
                        : ''}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
