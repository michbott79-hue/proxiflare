/**
 * index.ts — Snippet generator registry.
 * Exports TARGETS (all 10 generators) and generateSnippet() helper.
 * InspectEntry is the canonical input shape from Inspect.tsx.
 */

import type { InspectEntry } from './har.ts';
export type { InspectEntry };

import { generate as curlGen          } from './curl.ts';
import { generate as pyRequestsGen    } from './python-requests.ts';
import { generate as pyHttpxGen       } from './python-httpx.ts';
import { generate as nodeFetchGen     } from './node-fetch.ts';
import { generate as nodeAxiosGen     } from './node-axios.ts';
import { generate as phpCurlGen       } from './php-curl.ts';
import { generate as phpGuzzleGen     } from './php-guzzle.ts';
import { generate as goNetHttpGen     } from './go-nethttp.ts';
import { generate as rustReqwestGen   } from './rust-reqwest.ts';
import { generate as javaOkHttpGen    } from './java-okhttp.ts';

export type TargetId =
  | 'curl'
  | 'python-requests'
  | 'python-httpx'
  | 'node-fetch'
  | 'node-axios'
  | 'php-curl'
  | 'php-guzzle'
  | 'go-nethttp'
  | 'rust-reqwest'
  | 'java-okhttp';

export interface SnippetTarget {
  id:       TargetId;
  label:    string;
  lang:     'bash' | 'python' | 'javascript' | 'php' | 'go' | 'rust' | 'java';
  generate: (entry: InspectEntry) => string;
}

export const TARGETS: SnippetTarget[] = [
  { id: 'curl',            label: 'cURL',                lang: 'bash',       generate: curlGen        },
  { id: 'python-requests', label: 'Python: requests',    lang: 'python',     generate: pyRequestsGen  },
  { id: 'python-httpx',    label: 'Python: httpx',       lang: 'python',     generate: pyHttpxGen     },
  { id: 'node-fetch',      label: 'Node: fetch',         lang: 'javascript', generate: nodeFetchGen   },
  { id: 'node-axios',      label: 'Node: axios',         lang: 'javascript', generate: nodeAxiosGen   },
  { id: 'php-curl',        label: 'PHP: cURL',           lang: 'php',        generate: phpCurlGen     },
  { id: 'php-guzzle',      label: 'PHP: Guzzle',         lang: 'php',        generate: phpGuzzleGen   },
  { id: 'go-nethttp',      label: 'Go: net/http',        lang: 'go',         generate: goNetHttpGen   },
  { id: 'rust-reqwest',    label: 'Rust: reqwest',       lang: 'rust',       generate: rustReqwestGen },
  { id: 'java-okhttp',     label: 'Java: OkHttp',        lang: 'java',       generate: javaOkHttpGen  },
];

const TARGET_MAP = new Map<TargetId, SnippetTarget>(
  TARGETS.map(t => [t.id, t])
);

export function generateSnippet(target: TargetId, entry: InspectEntry): string {
  const t = TARGET_MAP.get(target);
  if (!t) throw new Error(`Unknown snippet target: ${target}`);
  return t.generate(entry);
}

// ---------------------------------------------------------------------------
// Test fixture — sample InspectEntry for manual verification
// ---------------------------------------------------------------------------

export const __testFixture: InspectEntry = {
  domain:       'api.example.com',
  dst_port:     443,
  tls:          true,
  method:       'POST',
  url:          '/v2/users?role=admin',
  version:      'HTTP/1.1',
  content_type: 'application/json',
  headers: {
    'Authorization': 'Bearer eyJhbGciOiJSUzI1NiJ9.test.token',
    'Content-Type':  'application/json',
    'User-Agent':    'ProxiFlare/0.1.0',
    'Cookie':        'session=abc123; pref=dark',
  },
  body: '{"name":"Alice","age":30}',
};
