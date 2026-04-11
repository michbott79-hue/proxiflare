import { useEffect, useRef, useState, useCallback } from 'react';
import type { RuleAction } from '../lib/types';
import { useLog } from '../hooks/useLog';

const ACTION_COLORS: Record<RuleAction, string> = {
  DIRECT: 'text-[#94a3b8]',
  PROXY: 'text-[#818cf8]',
  CHAIN: 'text-[#c084fc]',
  BLOCK: 'text-[#f87171]',
  REJECT: 'text-[#fbbf24]',
};

const FILTER_ACTIONS: (RuleAction | 'ALL')[] = ['ALL', 'DIRECT', 'PROXY', 'CHAIN', 'BLOCK', 'REJECT'];
const ROW_HEIGHT = 22; // px per log row
const OVERSCAN = 10;   // extra rows above/below viewport

function formatTime(ts: number): string {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString('en-GB', { hour12: false });
}

function formatBytes(bytes: number): string {
  if (!bytes) return '';
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
}

export default function Log() {
  const { entries, paused, toggle, clear } = useLog();
  const [filterApp, setFilterApp] = useState('');
  const [filterDomain, setFilterDomain] = useState('');
  const [filterAction, setFilterAction] = useState<RuleAction | 'ALL'>('ALL');
  const [showActionDd, setShowActionDd] = useState(false);
  const [search, setSearch] = useState('');
  const scrollRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [containerHeight, setContainerHeight] = useState(600);

  const filtered = entries.filter(entry => {
    if (filterApp && !(entry.app || '').toLowerCase().includes(filterApp.toLowerCase())) return false;
    if (filterDomain && !(entry.domain || '').toLowerCase().includes(filterDomain.toLowerCase())) return false;
    if (filterAction !== 'ALL' && entry.action !== filterAction) return false;
    if (search) {
      const s = search.toLowerCase();
      const line = `${entry.app} ${entry.domain} ${entry.dst_ip} ${entry.proxy} ${entry.rule}`.toLowerCase();
      if (!line.includes(s)) return false;
    }
    return true;
  });

  // Virtual scrolling: only render visible rows
  const totalHeight = filtered.length * ROW_HEIGHT;
  const startIdx = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const endIdx = Math.min(filtered.length, Math.ceil((scrollTop + containerHeight) / ROW_HEIGHT) + OVERSCAN);
  const visibleEntries = filtered.slice(startIdx, endIdx);
  const offsetY = startIdx * ROW_HEIGHT;

  const handleScroll = useCallback(() => {
    if (scrollRef.current) {
      setScrollTop(scrollRef.current.scrollTop);
    }
  }, []);

  // Auto-scroll to bottom when new entries arrive (unless paused)
  useEffect(() => {
    if (!paused && scrollRef.current) {
      scrollRef.current.scrollTop = totalHeight;
    }
  }, [filtered.length, paused, totalHeight]);

  // Measure container height
  useEffect(() => {
    if (scrollRef.current) {
      const ro = new ResizeObserver(([e]) => setContainerHeight(e.contentRect.height));
      ro.observe(scrollRef.current);
      return () => ro.disconnect();
    }
  }, []);

  return (
    <div className="flex h-full flex-col">
      {/* Top bar */}
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <input type="text" value={filterApp} onChange={e => setFilterApp(e.target.value)}
          placeholder="App" className="w-28 rounded-md border border-[#2d3348] bg-[#232733] px-3 py-1.5 text-xs text-[#e2e8f0] placeholder-[#64748b] outline-none focus:border-[#6366f1]" />
        <input type="text" value={filterDomain} onChange={e => setFilterDomain(e.target.value)}
          placeholder="Domain" className="w-36 rounded-md border border-[#2d3348] bg-[#232733] px-3 py-1.5 text-xs text-[#e2e8f0] placeholder-[#64748b] outline-none focus:border-[#6366f1]" />
        <div className="relative">
          <button type="button" onClick={() => setShowActionDd(p => !p)}
            className="flex w-32 items-center justify-between rounded-md border border-[#2d3348] bg-[#232733] px-3 py-1.5 text-xs text-[#e2e8f0]">
            <span>{filterAction}</span>
            <svg className="h-3 w-3 text-[#64748b]" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z" clipRule="evenodd" />
            </svg>
          </button>
          {showActionDd && (
            <div className="absolute z-50 mt-1 w-32 rounded-md border border-[#2d3348] bg-[#232733] py-1 shadow-xl">
              {FILTER_ACTIONS.map(a => (
                <button key={a} type="button"
                  onClick={() => { setFilterAction(a); setShowActionDd(false); }}
                  className="block w-full px-3 py-1.5 text-left text-xs text-[#e2e8f0] hover:bg-[#6366f1] hover:text-white transition-colors">
                  {a}
                </button>
              ))}
            </div>
          )}
        </div>
        <input type="text" value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Search..." className="w-40 rounded-md border border-[#2d3348] bg-[#232733] px-3 py-1.5 text-xs text-[#e2e8f0] placeholder-[#64748b] outline-none focus:border-[#6366f1]" />

        <div className="ml-auto flex items-center gap-2">
          <span className="text-xs text-[#64748b]">{filtered.length} entries</span>
          <button onClick={toggle}
            className={`rounded-md border px-3 py-1.5 text-xs transition-colors ${paused
              ? 'border-[#f59e0b]/30 text-[#f59e0b] hover:bg-[#f59e0b]/10'
              : 'border-[#2d3348] bg-[#232733] text-[#64748b] hover:text-[#e2e8f0]'}`}>
            {paused ? 'Resume' : 'Pause'}
          </button>
          <button onClick={clear}
            className="rounded-md border border-[#2d3348] bg-[#232733] px-3 py-1.5 text-xs text-[#64748b] transition-colors hover:text-[#e2e8f0]">
            Clear
          </button>
        </div>
      </div>

      {/* Log area — virtual scrolling */}
      <div
        ref={scrollRef}
        onScroll={handleScroll}
        className="flex-1 overflow-auto rounded-lg border border-[#2d3348] bg-[#0f1117] font-mono text-xs"
      >
        {filtered.length === 0 ? (
          <div className="flex h-full items-center justify-center text-[#64748b]">
            <div className="text-center">
              <p>Waiting for connections...</p>
              <p className="mt-1 text-[10px]">Log entries will appear here when the daemon is running</p>
            </div>
          </div>
        ) : (
          <div style={{ height: totalHeight, position: 'relative' }}>
            <div style={{ transform: `translateY(${offsetY}px)` }}>
              {visibleEntries.map((entry, i) => (
                <div
                  key={startIdx + i}
                  style={{ height: ROW_HEIGHT }}
                  className={`flex items-center px-2 ${ACTION_COLORS[entry.action as RuleAction] ?? 'text-[#94a3b8]'} hover:bg-[#1a1d27]`}
                >
                  <span className="text-[#64748b] w-[70px] shrink-0">[{formatTime(entry.ts)}]</span>
                  <span className={`w-[14px] shrink-0 ${entry.success ? 'text-[#4ade80]' : 'text-[#f87171]'}`}>
                    {entry.success ? '✓' : '✗'}
                  </span>
                  <span className="text-[#f59e0b] w-[100px] shrink-0 truncate" title={entry.app}>
                    {entry.app?.split('/').pop() || entry.rule || '?'}
                  </span>
                  <span className="text-[#64748b] shrink-0 mx-1">→</span>
                  <span className="text-[#e2e8f0] truncate" title={`${entry.domain || entry.dst_ip}:${entry.dst_port}`}>
                    {entry.domain || entry.dst_ip}
                    <span className="text-[#64748b]">:{entry.dst_port}</span>
                  </span>
                  <span className="text-[#64748b] shrink-0 mx-1">via</span>
                  <span className="text-[#818cf8] font-semibold shrink-0 truncate max-w-[100px]" title={entry.proxy}>
                    {entry.proxy || `#${entry.proxy_id}`}
                  </span>
                  {(entry.bytes_tx > 0 || entry.bytes_rx > 0) && (
                    <span className="text-[#64748b] shrink-0 ml-2">
                      {formatBytes(entry.bytes_tx)}↑{formatBytes(entry.bytes_rx)}↓
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
