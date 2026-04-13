import { useState, useEffect, useRef, useCallback } from 'react';
import { logRecent, type LogEntryRaw } from '../lib/api';

const MAX_ENTRIES = 10000;
const POLL_INTERVAL = 400; // ms — snappy real-time feel, daemon ring is in-memory

export function useLog() {
  const [entries, setEntries] = useState<LogEntryRaw[]>([]);
  const [paused, setPaused] = useState(false);
  const [dropped, setDropped] = useState(0);
  const seqRef = useRef(0);
  const pausedRef = useRef(false);

  useEffect(() => { pausedRef.current = paused; }, [paused]);

  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | null = null;
    let cancelled = false;

    const tick = async () => {
      if (!pausedRef.current) {
        try {
          const newEntries = await logRecent(seqRef.current);
          if (newEntries.length > 0) {
            /* Detect gaps: if the smallest new seq > last known seq + 1,
             * the daemon ring rolled over some entries before we polled. */
            const sorted = newEntries.slice().sort((a, b) => (a.seq || 0) - (b.seq || 0));
            const firstSeq = sorted[0]?.seq || 0;
            const lastSeq = sorted[sorted.length - 1]?.seq || 0;
            if (seqRef.current > 0 && firstSeq > seqRef.current + 1) {
              setDropped(d => d + (firstSeq - seqRef.current - 1));
            }
            if (lastSeq > seqRef.current) seqRef.current = lastSeq;

            setEntries(prev => {
              const next = prev.length + sorted.length > MAX_ENTRIES
                ? prev.slice(prev.length + sorted.length - MAX_ENTRIES).concat(sorted)
                : prev.concat(sorted);
              return next;
            });
          }
        } catch {
          /* daemon not connected — silent retry */
        }
      }
      if (!cancelled) timer = setTimeout(tick, POLL_INTERVAL);
    };
    tick();

    return () => { cancelled = true; if (timer) clearTimeout(timer); };
  }, []);

  const pause = useCallback(() => setPaused(true), []);
  const resume = useCallback(() => setPaused(false), []);
  const clear = useCallback(() => { setEntries([]); setDropped(0); }, []);
  const toggle = useCallback(() => setPaused(p => !p), []);

  return { entries, paused, dropped, pause, resume, toggle, clear };
}
