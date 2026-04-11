import { invoke } from '@tauri-apps/api/core';
import type { Proxy, Rule, Chain, DaemonStatus } from './types';

// ── Proxy commands ──────────────────────────────────────────────

export async function proxyList(): Promise<Proxy[]> {
  return invoke<Proxy[]>('proxy_list');
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
  return invoke<Rule[]>('rule_list');
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
  return invoke<Chain[]>('chain_list');
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
