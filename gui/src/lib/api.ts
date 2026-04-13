import { invoke } from '@tauri-apps/api/core';
import type { Proxy, Rule, Chain, DaemonStatus } from './types';

// ── Proxy commands ──────────────────────────────────────────────

export async function proxyList(): Promise<Proxy[]> {
  const r = await invoke<unknown>('proxy_list');
  return Array.isArray(r) ? (r as Proxy[]) : [];
}

export async function proxyAdd(proxy: Omit<Proxy, 'id' | 'health' | 'latency_ms'>): Promise<Proxy> {
  return invoke<Proxy>('proxy_add', {
    name: proxy.name,
    proxyType: proxy.type,
    host: proxy.host,
    port: proxy.port,
    username: proxy.username || '',
    password: proxy.password || '',
    checkInterval: proxy.check_interval || 60,
  });
}

export async function proxyEdit(proxy: Proxy): Promise<Proxy> {
  return invoke<Proxy>('proxy_edit', {
    id: proxy.id,
    name: proxy.name,
    proxyType: proxy.type,
    host: proxy.host,
    port: proxy.port,
    username: proxy.username || '',
    password: proxy.password || '',
    checkInterval: proxy.check_interval || 60,
    enabled: proxy.enabled,
  });
}

export async function proxyDelete(id: number): Promise<void> {
  return invoke<void>('proxy_delete', { id });
}

export async function proxyTest(id: number): Promise<{ ok: boolean; latency_ms: number | null; error?: string }> {
  return invoke('proxy_test', { id });
}

// ── Rule commands ───────────────────────────────────────────────

export async function ruleList(): Promise<Rule[]> {
  const r = await invoke<unknown>('rule_list');
  return Array.isArray(r) ? (r as Rule[]) : [];
}

export async function ruleAdd(rule: Omit<Rule, 'id'>): Promise<Rule> {
  return invoke<Rule>('rule_add', {
    name: rule.name,
    priority: rule.priority,
    matchApp: rule.match_app || '',
    matchDomain: rule.match_domain || '',
    matchIp: rule.match_ip || '',
    matchPort: rule.match_port || '',
    action: rule.action,
    proxyId: rule.proxy_id ?? -1,
    chainId: rule.chain_id ?? -1,
  });
}

export async function ruleEdit(rule: Rule): Promise<Rule> {
  return invoke<Rule>('rule_edit', {
    id: rule.id,
    name: rule.name,
    enabled: rule.enabled,
    priority: rule.priority,
    matchApp: rule.match_app || '',
    matchDomain: rule.match_domain || '',
    matchIp: rule.match_ip || '',
    matchPort: rule.match_port || '',
    action: rule.action,
    proxyId: rule.proxy_id ?? -1,
    chainId: rule.chain_id ?? -1,
  });
}

export async function ruleDelete(id: number): Promise<void> {
  return invoke<void>('rule_delete', { id });
}

export async function ruleReorder(ids: number[]): Promise<void> {
  return invoke<void>('rule_reorder', { ids });
}

// ── Chain commands ──────────────────────────────────────────────

export async function chainList(): Promise<Chain[]> {
  const r = await invoke<unknown>('chain_list');
  return Array.isArray(r) ? (r as Chain[]) : [];
}

export async function chainAdd(chain: Omit<Chain, 'id'>): Promise<Chain> {
  return invoke<Chain>('chain_add', {
    name: chain.name,
    hopProxyIds: chain.hop_proxy_ids,
  });
}

export async function chainEdit(chain: Chain): Promise<Chain> {
  return invoke<Chain>('chain_edit', {
    id: chain.id,
    name: chain.name,
    hopProxyIds: chain.hop_proxy_ids,
  });
}

export async function chainDelete(id: number): Promise<void> {
  return invoke<void>('chain_delete', { id });
}

export async function chainTest(id: number): Promise<{ ok: boolean; latency_ms: number | null; error?: string }> {
  return invoke('chain_test', { id });
}

// ── Config commands ─────────────────────────────────────────────

export async function configGet(key: string): Promise<string | null> {
  return invoke<string | null>('config_get', { key });
}

export async function configSet(key: string, value: string): Promise<void> {
  return invoke<void>('config_set', { key, value });
}

// ── Credentials commands ────────────────────────────────────────

export async function credentialsUnlock(password: string): Promise<boolean> {
  return invoke<boolean>('credentials_unlock', { password });
}

export async function credentialsLock(): Promise<void> {
  return invoke<void>('credentials_lock');
}

// ── System commands ─────────────────────────────────────────────

export async function systemStatus(): Promise<DaemonStatus> {
  return invoke<DaemonStatus>('system_status');
}

export async function systemVersion(): Promise<string> {
  return invoke<string>('system_version');
}

// ── DNS leak protection ─────────────────────────────────────────

export type DnsMode = 'force-server' | 'via-proxy';

export async function dnsLeakEnable(dnsServer: string, mode: DnsMode = 'force-server'): Promise<void> {
  return invoke<void>('dns_leak_enable', { dnsServer, mode });
}

export async function dnsLeakDisable(): Promise<void> {
  return invoke<void>('dns_leak_disable');
}

export async function dnsLeakStatus(): Promise<{ enabled: boolean; mode: DnsMode; dns_server: string }> {
  const raw = await invoke<any>('dns_leak_status');
  const r = raw?.result ?? raw ?? {};
  return {
    enabled:    !!r.enabled,
    mode:       (r.mode === 'via-proxy' ? 'via-proxy' : 'force-server') as DnsMode,
    dns_server: r.dns_server ?? '1.1.1.1',
  };
}

// ── Log polling ─────────────────────────────────────────────────────────────

export interface LogEntryRaw {
  ts: number;
  app: string;       // app path or rule name
  rule: string;      // rule name
  proxy: string;     // proxy name
  proxy_id: number;
  domain: string;
  dst_ip: string;
  dst_port: number;
  action: string;
  success: number;
  bytes_tx: number;
  bytes_rx: number;
  latency_ms: number;
  seq: number;
}

export async function logRecent(sinceSeq: number): Promise<LogEntryRaw[]> {
  /* Same double-wrap unwrap as inspectList — daemon returns {"result":[...]} */
  const raw = await invoke<any>('log_recent', { sinceSeq });
  const arr = raw?.result ?? raw;
  return Array.isArray(arr) ? arr : [];
}

// ── Inspect (MITM HTTP interception) ───────────────────────────────────────

export async function inspectList(sinceSeq: number): Promise<any[]> {
  /* Daemon returns {"result": {"result": [...]}}. Tauri's send_request
   * unwraps the outer layer; we still need to unwrap the inner `result`
   * field. Mirror the same defensive chain used in inspectStatus. */
  const raw = await invoke<any>('inspect_list', { sinceSeq });
  const arr = raw?.result ?? raw;
  return Array.isArray(arr) ? arr : [];
}

export async function inspectEnable(): Promise<void> {
  return invoke<void>('inspect_enable');
}

export async function inspectDisable(): Promise<void> {
  return invoke<void>('inspect_disable');
}

export async function inspectStatus(): Promise<any> {
  const raw = await invoke<any>('inspect_status');
  return raw?.result ?? raw ?? { enabled: false, ca_installed: false };
}

export async function inspectGenerateCa(): Promise<void> {
  return invoke<void>('inspect_generate_ca');
}

// ── Provider import (proxy-cheap, …) ────────────────────────────

export interface ProviderInfo {
  id: string;
  name: string;
}

export interface ImportResult {
  fetched: number;
  added: number;
  skipped: number;
  failed: number;
  errors: string[];
}

export async function providersList(): Promise<ProviderInfo[]> {
  const raw = await invoke<Array<[string, string]>>('providers_list');
  return raw.map(([id, name]) => ({ id, name }));
}

export async function providersImport(
  providerId: string,
  apiKey: string,
  apiSecret: string,
): Promise<ImportResult> {
  return invoke<ImportResult>('providers_import', { providerId, apiKey, apiSecret });
}

// ── System apps ─────────────────────────────────────────────────

export interface SystemApp {
  name: string;
  exec: string;
  icon: string;
}

export async function listSystemApps(): Promise<SystemApp[]> {
  return invoke<SystemApp[]>('list_system_apps');
}
