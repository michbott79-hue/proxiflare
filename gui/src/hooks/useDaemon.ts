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
  // Once unlocked in this session, stay unlocked
  const unlockedRef = useRef(false);

  const poll = useCallback(async () => {
    try {
      const raw = await systemStatus();
      const s: DaemonStatus = (raw as any)?.result ?? raw ?? DEFAULT_STATUS;
      // If daemon says crypto is unlocked, or we already unlocked this session
      const daemonUnlocked = (s as any).crypto_unlocked === true;
      if (daemonUnlocked) unlockedRef.current = true;
      setState({
        status: s,
        connected: true,
        unlocked: unlockedRef.current,
        error: null,
      });
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes('locked') || msg.includes('Locked')) {
        setState({
          status: DEFAULT_STATUS,
          connected: true,
          unlocked: unlockedRef.current,
          error: null,
        });
      } else {
        setState(prev => ({
          status: DEFAULT_STATUS,
          connected: false,
          unlocked: prev.unlocked,
          error: msg,
        }));
      }
    }
  }, []);

  const setUnlocked = useCallback((val: boolean) => {
    unlockedRef.current = val;
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
