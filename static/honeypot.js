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

export async function getLiveConnections(minutes = 15, limit = 100) {
  return apiGet(`/api/v1/live/connections?minutes=${minutes}&limit=${limit}`, { timeout: 30000, retries: 2 });
}

// LLM Analysis endpoints
export async function analyzeSession(sessionId) {
  return apiPost('/api/v1/llm/analyze/session', { session_id: sessionId, save: true }, { timeout: 120000, retries: 1 });
}

export async function examineArtifact(artifactName) {
  return apiPost('/api/v1/llm/examine/artifact', { artifact_name: artifactName }, { timeout: 120000, retries: 1 });
}

export async function generateCountermeasure(threatAnalysisId, context = {}) {
  return apiPost('/api/v1/llm/countermeasure', { threat_analysis_id: threatAnalysisId, context }, { timeout: 120000, retries: 1 });
}

export async function unifyThreats(sessionIds) {
  return apiPost('/api/v1/llm/unify', { session_ids: sessionIds }, { timeout: 120000, retries: 1 });
}

// Vector search endpoints
export async function indexSession(sessionId) {
  return apiPost('/api/v1/vector/index/session', { session_id: sessionId }, { timeout: 60000, retries: 1 });
}

export async function findSimilarSessions(sessionId, limit = 10) {
  return apiGet(`/api/v1/vector/search/sessions?session_id=${sessionId}&limit=${limit}`, { timeout: 30000, retries: 2 });
}

export async function searchSessions(query, limit = 10) {
  return apiGet(`/api/v1/vector/search/sessions?q=${encodeURIComponent(query)}&limit=${limit}`, { timeout: 30000, retries: 2 });
}

// Threat analysis endpoints
export async function listThreats(sourceType = null, limit = 100) {
  const params = new URLSearchParams({ limit });
  if (sourceType) params.append('type', sourceType);
  return apiGet(`/api/v1/threats?${params}`, { timeout: 30000, retries: 2 });
}

export async function getThreat(id) {
  return apiGet(`/api/v1/threat?id=${id}`, { timeout: 30000, retries: 2 });
}

// Cluster endpoints
export async function listClusters(limit = 100) {
  return apiGet(`/api/v1/clusters?limit=${limit}`, { timeout: 30000, retries: 2 });
}

export async function getCluster(id) {
  return apiGet(`/api/v1/cluster?id=${id}`, { timeout: 30000, retries: 2 });
}

export async function createCluster(sessionIds, name = null) {
  return apiPost('/api/v1/cluster', { session_ids: sessionIds, name }, { timeout: 60000, retries: 1 });
}

// Similar attackers endpoint
export async function findSimilarAttackers(ip, threshold = 0.7, limit = 10) {
  return apiGet(`/api/v1/similar/attackers?ip=${encodeURIComponent(ip)}&threshold=${threshold}&limit=${limit}`, { timeout: 30000, retries: 2 });
}
