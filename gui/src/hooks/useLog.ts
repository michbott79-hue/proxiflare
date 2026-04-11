import { useState, useEffect, useRef, useCallback } from 'react';
import type { LogEntry } from '../lib/types';

const MAX_ENTRIES = 10000;

export function useLog() {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [paused, setPaused] = useState(false);
  const pausedRef = useRef(false);

  useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);

  useEffect(() => {
    let unlisten: (() => void) | null = null;

    async function setup() {
      try {
        const { listen } = await import('@tauri-apps/api/event');
        const un = await listen<LogEntry>('log-entry', (event) => {
          if (pausedRef.current) return;
          setEntries(prev => {
            const next = [...prev, event.payload];
            if (next.length > MAX_ENTRIES) {
              return next.slice(next.length - MAX_ENTRIES);
            }
            return next;
          });
        });
        unlisten = un;
      } catch {
        // Tauri event system not available (dev mode outside Tauri)
      }
    }

    setup();
    return () => {
      if (unlisten) unlisten();
    };
  }, []);

  const pause = useCallback(() => setPaused(true), []);
  const resume = useCallback(() => setPaused(false), []);
  const clear = useCallback(() => setEntries([]), []);
  const toggle = useCallback(() => setPaused(p => !p), []);

  return { entries, paused, pause, resume, toggle, clear };
}
