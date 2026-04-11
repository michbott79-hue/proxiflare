import { useState, useEffect, useRef, useCallback } from 'react';
import type { DaemonStatus } from '../lib/types';
import { systemStatus } from '../lib/api';

interface DaemonState {
  status: DaemonStatus | null;
  connected: boolean;
  unlocked: boolean;
  error: string | null;
}

const DEFAULT_STATUS: DaemonStatus = {
  running: false,
  version: '',
  connections: 0,
  proxies_online: 0,
  rules_active: 0,
};

export function useDaemon() {
  const [state, setState] = useState<DaemonState>({
    status: null,
    connected: false,
    unlocked: false,
    error: null,
  });
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const poll = useCallback(async () => {
    try {
      const s = await systemStatus();
      setState({
        status: s,
        connected: true,
        unlocked: true,
        error: null,
      });
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      // If the error indicates locked credentials, mark as connected but not unlocked
      if (msg.includes('locked') || msg.includes('Locked')) {
        setState({
          status: DEFAULT_STATUS,
          connected: true,
          unlocked: false,
          error: null,
        });
      } else {
        setState({
          status: DEFAULT_STATUS,
          connected: false,
          unlocked: false,
          error: msg,
        });
      }
    }
  }, []);

  const setUnlocked = useCallback((val: boolean) => {
    setState(prev => ({ ...prev, unlocked: val }));
  }, []);

  useEffect(() => {
    poll();
    intervalRef.current = setInterval(poll, 2000);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [poll]);

  return { ...state, setUnlocked, refresh: poll };
}
