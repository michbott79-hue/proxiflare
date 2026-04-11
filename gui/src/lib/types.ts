export type ProxyType = 'socks4' | 'socks5' | 'http' | 'ssh';
export type HealthStatus = 'unknown' | 'online' | 'offline' | 'slow' | 'error';
export type RuleAction = 'DIRECT' | 'PROXY' | 'CHAIN' | 'BLOCK' | 'REJECT';

export interface Proxy {
  id: number;
  name: string;
  type: ProxyType;
  host: string;
  port: number;
  username?: string;
  password?: string;
  enabled: boolean;
  health: HealthStatus;
  latency_ms: number | null;
  check_interval: number;
}

export interface Rule {
  id: number;
  name: string;
  enabled: boolean;
  priority: number;
  match_app?: string;
  match_domain?: string;
  match_ip?: string;
  match_port?: string;
  action: RuleAction;
  proxy_id?: number;
  chain_id?: number;
}

export interface Chain {
  id: number;
  name: string;
  enabled: boolean;
  hop_proxy_ids: number[];
}

export interface LogEntry {
  ts: number;
  app: string;
  pid: number;
  domain: string;
  dst_ip: string;
  dst_port: number;
  proxy: string;
  action: RuleAction;
  bytes_tx: number;
  bytes_rx: number;
  latency_ms: number;
}

export interface DaemonStatus {
  running: boolean;
  version: string;
  connections: number;
  proxies_online: number;
  rules_active: number;
}
