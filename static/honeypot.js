import { apiGet, apiPost } from './api.js';

// Thin wrappers for honeypot endpoints; return raw fetch results with retries
export async function listSessions(limit = 100) {
  return apiGet(`/api/v1/honeypot/sessions?limit=${limit}`, { timeout: 30000, retries: 2 });
}

export async function viewSession(id) {
  return apiGet(`/api/v1/honeypot/session?id=${encodeURIComponent(id)}`, { timeout: 30000, retries: 2 });
}

export async function ingestCowrie(path) {
  return apiPost('/api/v1/honeypot/ingest', { path }, { timeout: 120000, retries: 1 });
}

export async function ingestPcap(path, filter_host = null) {
  return apiPost('/api/v1/honeypot/ingest_pcap', { path, filter_host }, { timeout: 180000, retries: 1 });
}

export function artifactDownloadUrl(name) {
  return `/api/v1/honeypot/artifact?name=${encodeURIComponent(name)}`;
}

export async function listFlows(limit = 100) {
  return apiGet(`/api/v1/honeypot/flows?limit=${limit}`, { timeout: 30000, retries: 2 });
}
