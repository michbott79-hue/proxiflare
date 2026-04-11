import { useState, useEffect, useRef, useCallback } from 'react';
import { logRecent, type LogEntryRaw } from '../lib/api';

const MAX_ENTRIES = 5000;
const POLL_INTERVAL = 1000; // ms

export function useLog() {
  const [entries, setEntries] = useState<LogEntryRaw[]>([]);
  const [paused, setPaused] = useState(false);
  const seqRef = useRef(0);
  const pausedRef = useRef(false);

  useEffect(() => { pausedRef.current = paused; }, [paused]);

  useEffect(() => {
    const timer = setInterval(async () => {
      if (pausedRef.current) return;
      try {
        const newEntries = await logRecent(seqRef.current);
        if (newEntries.length > 0) {
          const maxSeq = Math.max(...newEntries.map(e => e.seq || 0));
          if (maxSeq > seqRef.current) seqRef.current = maxSeq;

          setEntries(prev => {
            const next = [...prev, ...newEntries];
            return next.length > MAX_ENTRIES ? next.slice(-MAX_ENTRIES) : next;
          });
        }
      } catch {
        // Daemon not connected — silent, will retry next interval
      }
    }, POLL_INTERVAL);

    return () => clearInterval(timer);
  }, []);

  const pause = useCallback(() => setPaused(true), []);
  const resume = useCallback(() => setPaused(false), []);
  const clear = useCallback(() => { setEntries([]); }, []);
  const toggle = useCallback(() => setPaused(p => !p), []);

  return { entries, paused, pause, resume, toggle, clear };
}
