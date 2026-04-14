/**
 * har.ts — Convert InspectEntry to a HAR-shaped request intermediate.
 * Canonical input for every snippet generator (mirrors httpsnippet pattern).
 * Strips headers that clients regenerate; parses cookies, query strings, body.
 */

export interface HarHeader   { name: string; value: string }
export interface HarQuery    { name: string; value: string }
export interface HarCookie   { name: string; value: string }
export interface HarPostData { mimeType: string; text: string; isBinary: boolean }

export interface HarRequest {
  method:      string;
  url:         string;       // full: scheme://host/path?query
  httpVersion: string;
  headers:     HarHeader[];
  queryString: HarQuery[];
  postData:    HarPostData | null;
  cookies:     HarCookie[];
}

/** Headers stripped before exposing to generators (clients auto-add them). */
const STRIP_HEADERS = new Set([
  'content-length',
  'content-encoding',
  'transfer-encoding',
  'host',
  'connection',
]);

function stripHeaders(raw: Record<string, string>): HarHeader[] {
  return Object.entries(raw)
    .filter(([k]) => {
      const lo = k.toLowerCase();
      return !STRIP_HEADERS.has(lo) && !lo.startsWith(':');
    })
    .map(([name, value]) => ({ name, value }));
}

function parseCookies(raw: Record<string, string>): HarCookie[] {
  const cookieHeader = Object.entries(raw).find(
    ([k]) => k.toLowerCase() === 'cookie'
  );
  if (!cookieHeader) return [];
  return cookieHeader[1]
    .split(';')
    .map(part => {
      const idx = part.indexOf('=');
      if (idx < 0) return null;
      return { name: part.slice(0, idx).trim(), value: part.slice(idx + 1).trim() };
    })
    .filter((c): c is HarCookie => c !== null);
}

function parseQuery(search: string): HarQuery[] {
  if (!search) return [];
  const qs = search.startsWith('?') ? search.slice(1) : search;
  return qs
    .split('&')
    .filter(Boolean)
    .map(part => {
      const idx = part.indexOf('=');
      if (idx < 0) return { name: decodeURIComponent(part), value: '' };
      return {
        name:  decodeURIComponent(part.slice(0, idx)),
        value: decodeURIComponent(part.slice(idx + 1)),
      };
    });
}

function isBinaryBody(body: string): boolean {
  // heuristic: contains null bytes or high proportion of non-printable chars
  for (let i = 0; i < Math.min(body.length, 512); i++) {
    const c = body.charCodeAt(i);
    if (c === 0) return true;
  }
  return false;
}

/** InspectEntry shape — only fields we need here. */
export interface InspectEntry {
  domain:    string;
  dst_port:  number;
  tls:       boolean;
  method?:   string;
  url?:      string;   // path + query only
  version?:  string;
  headers:   Record<string, string>;
  body?:     string;
  content_type?: string;
}

export function toHar(entry: InspectEntry): HarRequest {
  const scheme = entry.tls ? 'https' : 'http';
  const pathFull = entry.url || '/';
  const qIdx = pathFull.indexOf('?');
  const path   = qIdx >= 0 ? pathFull.slice(0, qIdx) : pathFull;
  const search = qIdx >= 0 ? pathFull.slice(qIdx)    : '';

  const url = `${scheme}://${entry.domain}${path}${search}`;

  const method = (entry.method || 'GET').toUpperCase();

  // detect mime from explicit header or content_type field
  const ctHeader = Object.entries(entry.headers).find(
    ([k]) => k.toLowerCase() === 'content-type'
  );
  const mimeType = ctHeader?.[1] ?? entry.content_type ?? 'application/octet-stream';

  let postData: HarPostData | null = null;
  if (entry.body) {
    const binary = isBinaryBody(entry.body);
    postData = { mimeType, text: entry.body, isBinary: binary };
  }

  return {
    method,
    url,
    httpVersion: entry.version || 'HTTP/1.1',
    headers:     stripHeaders(entry.headers),
    queryString: parseQuery(search),
    postData,
    cookies:     parseCookies(entry.headers),
  };
}
