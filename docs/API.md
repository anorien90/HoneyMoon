# HoneyMoon API Reference

This document provides detailed documentation for all API endpoints available in HoneyMoon.

## Base URL

```
http://localhost:5000
```

## Response Format

All API responses return JSON with the following structure:

**Success:**
```json
{
  "data": { ... },
  "status": 200
}
```

**Error:**
```json
{
  "error": "Error message description"
}
```

---

## Core Endpoints

### Health Check

Check if the API is running.

```http
GET /api/v1/health
```

**Response:**
```json
{
  "status": "ok"
}
```

---

## IP Intelligence

### Locate IP

Get geolocation and intelligence data for an IP address.

```http
GET /api/v1/locate?ip=<ip_address>
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| ip | string | Yes | IPv4 address to locate |

**Response:**
```json
{
  "node": {
    "ip": "8.8.8.8",
    "hostname": "dns.google",
    "organization": "Google LLC",
    "organization_id": 1,
    "organization_obj": {
      "id": 1,
      "name": "Google LLC",
      "name_normalized": "google llc",
      "rdap": { ... },
      "abuse_email": "abuse@google.com"
    },
    "isp": "Google LLC",
    "asn": "AS15169 Google LLC",
    "country": "United States",
    "city": "Mountain View",
    "latitude": 37.386,
    "longitude": -122.084,
    "is_tor_exit": false,
    "first_seen": "2024-01-15T10:30:00Z",
    "last_seen": "2024-01-15T14:20:00Z",
    "seen_count": 5,
    "extra_data": {
      "fingerprints": { ... }
    },
    "path_hops": [],
    "web_accesses_count": 12
  },
  "organization": {
    "id": 1,
    "name": "Google LLC",
    "rdap": { ... }
  }
}
```

**Errors:**
- `400` - No IP provided
- `404` - IP not found in database

---

### Trace Route

Perform a traceroute analysis to a target IP.

```http
GET /api/v1/trace?ip=<ip>&deep=<0|1>&maxttl=<int>
```

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| ip | string | Yes | - | Target IPv4 address |
| deep | string | No | 0 | Enable deep scanning (1=yes, 0=no) |
| maxttl | int | No | 30 | Maximum TTL for traceroute |

**Response:**
```json
{
  "session": {
    "session_id": 42,
    "target_ip": "8.8.8.8",
    "path": [
      {
        "hop_number": 1,
        "probe_index": 1,
        "ip": "192.168.1.1",
        "rtt": 0.0015,
        "organization": "Private Network",
        "country": null
      },
      {
        "hop_number": 2,
        "probe_index": 1,
        "ip": "10.0.0.1",
        "rtt": 0.0082,
        "organization": "ISP Network",
        "country": "United States"
      }
    ]
  },
  "nodes": {
    "192.168.1.1": {
      "ip": "192.168.1.1",
      "hostname": "router.local",
      "latitude": null,
      "longitude": null,
      ...
    },
    "10.0.0.1": {
      "ip": "10.0.0.1",
      "latitude": 37.774,
      "longitude": -122.419,
      ...
    }
  }
}
```

**Deep Mode:**
When `deep=1`, additional fingerprinting is performed:
- HTTP headers and security headers analysis
- TLS/SSL certificate inspection
- SSH banner grabbing
- nmap service detection

**Errors:**
- `400` - No IP provided
- `500` - Traceroute failed (with error details)

---

### Search

Search for nodes or organizations.

```http
GET /api/v1/search?type=<type>&q=<query>&fuzzy=<0|1>&limit=<int>
```

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| type | string | No | node | Search type: `node` or `org`/`organization` |
| q | string | No | - | Search query |
| fuzzy | string | No | 0 | Enable fuzzy matching (1=yes, 0=no) |
| limit | int | No | 100 | Maximum results to return |

**Response (nodes):**
```json
{
  "type": "node",
  "query": "google",
  "fuzzy": true,
  "results": [
    {
      "ip": "8.8.8.8",
      "hostname": "dns.google",
      "organization": "Google LLC",
      ...
    }
  ]
}
```

**Response (organizations):**
```json
{
  "type": "organization",
  "query": "Google",
  "fuzzy": false,
  "results": [
    {
      "id": 1,
      "name": "Google LLC",
      "name_normalized": "google llc",
      "rdap": { ... }
    }
  ]
}
```

---

### Get Accesses

Get web access records for an IP address.

```http
GET /api/v1/accesses?ip=<ip>&limit=<int>
```

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| ip | string | Yes | - | IP address to query |
| limit | int | No | 100 | Maximum results to return |

**Response:**
```json
{
  "ip": "192.168.1.100",
  "accesses": [
    {
      "id": 1,
      "timestamp": "2024-01-15T10:30:00Z",
      "remote_addr": "192.168.1.100",
      "remote_port": 54321,
      "request": "GET /api/health HTTP/1.1",
      "method": "GET",
      "path": "/api/health",
      "status": 200,
      "body_bytes_sent": 1234,
      "http_user_agent": "Mozilla/5.0...",
      "server_name": "api.example.com",
      "request_time": 0.015
    }
  ]
}
```

---

## Organization Endpoints

### Get Organization

Get organization details by IP or organization ID.

```http
GET /api/v1/organization?ip=<ip>
GET /api/v1/organization?id=<org_id>
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| ip | string | One of ip/id | IP address to lookup organization |
| id | int | One of ip/id | Organization ID |

**Response:**
```json
{
  "organization": {
    "id": 1,
    "name": "Google LLC",
    "name_normalized": "google llc",
    "rdap": {
      "provider": "GOOGLE",
      "org_full_name": "Google LLC",
      "abuse_email": "abuse@google.com",
      "registration_date": "2000-03-30T00:00:00Z"
    },
    "abuse_email": "abuse@google.com",
    "created_at": "2024-01-15T10:30:00Z",
    "extra_data": {
      "company_search": {
        "source": "opencorporates",
        "name": "Google LLC",
        "company_number": "3582691",
        "jurisdiction_code": "us_de",
        "company_url": "https://opencorporates.com/companies/us_de/3582691"
      }
    }
  }
}
```

**Errors:**
- `400` - No ip or id provided / Invalid organization id
- `404` - Organization not found

---

### Refresh Organization

Trigger a refresh of organization data from external sources.

```http
GET /api/v1/organization/refresh?id=<identifier>&force=<0|1>
```

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| id | string | Yes | - | IP address, org ID, or org name |
| force | string | No | 1 | Force refresh even if data exists |

**Response:**
```json
{
  "organization": {
    "id": 1,
    "name": "Google LLC",
    "extra_data": {
      "company_search": { ... }
    }
  }
}
```

**Errors:**
- `400` - No identifier provided
- `404` - Organization not found or enrichment failed
- `501` - Refresh function not available

---

## Honeypot Endpoints

### List Honeypot Sessions

List all honeypot sessions.

```http
GET /api/v1/honeypot/sessions?limit=<int>
```

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| limit | int | No | 200 | Maximum sessions to return |

**Response:**
```json
{
  "sessions": [
    {
      "id": 1,
      "cowrie_session": "abc123def456",
      "src_ip": "192.168.1.100",
      "src_port": 54321,
      "username": "root",
      "auth_success": "failed",
      "start_ts": "2024-01-15T10:30:00Z",
      "end_ts": "2024-01-15T10:31:30Z",
      "extra": {
        "node_cached": {
          "ip": "192.168.1.100",
          "organization": "Suspicious ISP",
          "asn": "AS12345",
          "country": "Unknown"
        }
      },
      "raw_events_count": 15
    }
  ]
}
```

---

### Get Honeypot Session

Get detailed information about a specific honeypot session.

```http
GET /api/v1/honeypot/session?id=<session_id>
GET /api/v1/honeypot/session?cowrie_session=<cowrie_session_id>
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| id | int | One of id/cowrie_session | Internal session ID |
| cowrie_session | string | One of id/cowrie_session | Cowrie session identifier |

**Response:**
```json
{
  "session": {
    "id": 1,
    "cowrie_session": "abc123def456",
    "src_ip": "192.168.1.100",
    "src_port": 54321,
    "username": "root",
    "auth_success": "failed",
    "start_ts": "2024-01-15T10:30:00Z",
    "end_ts": "2024-01-15T10:31:30Z",
    "commands": [
      {
        "id": 1,
        "session_id": 1,
        "timestamp": "2024-01-15T10:30:15Z",
        "command": "whoami"
      },
      {
        "id": 2,
        "session_id": 1,
        "timestamp": "2024-01-15T10:30:20Z",
        "command": "cat /etc/passwd"
      }
    ],
    "files": [
      {
        "id": 1,
        "session_id": 1,
        "timestamp": "2024-01-15T10:31:00Z",
        "filename": "malware.sh",
        "direction": "download",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "saved_path": "/data/honeypot/artifacts/e3b0c44_malware.sh"
      }
    ]
  }
}
```

**Errors:**
- `400` - No id or cowrie_session provided
- `404` - Session not found
- `500` - Honeypot models not available

---

### Ingest Cowrie Logs

Trigger ingestion of a Cowrie JSON log file.

```http
POST /api/v1/honeypot/ingest
Content-Type: application/json
```

**Request Body:**
```json
{
  "path": "/data/honeypot/log/cowrie.json"
}
```

**Response:**
```json
{
  "lines_processed": 1500,
  "errors": 3
}
```

**Errors:**
- `400` - No path provided / Path must be inside honeypot data directory
- `500` - Ingest failed (with error details)

**Security Note:** The path must be within the configured honeypot data directory to prevent path traversal attacks.

---

### Ingest PCAP

Trigger ingestion of a PCAP file for network flow analysis.

```http
POST /api/v1/honeypot/ingest_pcap
Content-Type: application/json
```

**Request Body:**
```json
{
  "path": "/data/honeypot/capture.pcap",
  "filter_host": "192.168.1.1"
}
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| path | string | Yes | Path to PCAP file |
| filter_host | string | No | Only include flows involving this host |

**Response:**
```json
{
  "flows": 250
}
```

**Errors:**
- `400` - No path provided / Path must be inside honeypot data directory
- `500` - PCAP ingest failed (with error details)

---

### Download Artifact

Download a captured artifact from a honeypot session.

```http
GET /api/v1/honeypot/artifact?name=<filename>
```

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| name | string | Yes | Artifact filename |

**Response:**
- Binary file download

**Errors:**
- `400` - No artifact name provided
- `404` - Artifact not found

**Security Note:** Files are served only from the artifacts directory to prevent path traversal.

---

### List Network Flows

List network flows from PCAP analysis.

```http
GET /api/v1/honeypot/flows?limit=<int>
```

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| limit | int | No | 200 | Maximum flows to return |

**Response:**
```json
{
  "flows": [
    {
      "id": 1,
      "src_ip": "192.168.1.100",
      "dst_ip": "8.8.8.8",
      "src_port": 54321,
      "dst_port": 53,
      "proto": "udp",
      "bytes": 1024,
      "packets": 5,
      "start_ts": "2024-01-15T10:30:00Z",
      "end_ts": "2024-01-15T10:30:01Z"
    }
  ]
}
```

---

## Database Explorer Endpoints

### Database Search

Unified search across all database tables.

```http
GET /api/v1/db/search?type=<type>&q=<query>&fuzzy=<0|1>&limit=<int>
```

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| type | string | No | node | Table to search (see below) |
| q | string | No | - | Search query |
| fuzzy | string | No | 0 | Enable fuzzy matching |
| limit | int | No | 200 | Maximum results |

**Supported Types:**
| Type | Description |
|------|-------------|
| `node` / `nodes` | Network nodes |
| `org` / `organization` / `orgs` | Organizations |
| `honeypot` / `session` / `sessions` | Honeypot sessions |
| `access` / `accesses` / `webaccess` | Web access logs |
| `analysis` / `analyses` / `trace` | Analysis sessions |
| `flow` / `flows` | Network flows |

**Response varies by type.**

---

### Get Node Details

Get comprehensive details for a specific network node.

```http
GET /api/v1/db/node?ip=<ip>&limit=<int>
```

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| ip | string | Yes | - | IP address |
| limit | int | No | 50 | Max related records per category |

**Response:**
```json
{
  "node": {
    "ip": "192.168.1.100",
    "hostname": "attacker.example.com",
    "organization": "Suspicious ISP",
    ...
  },
  "recent_accesses": [
    {
      "id": 1,
      "timestamp": "2024-01-15T10:30:00Z",
      "path": "/wp-admin",
      ...
    }
  ],
  "analyses": [
    {
      "id": 1,
      "timestamp": "2024-01-15T10:00:00Z",
      "target_ip": "192.168.1.100",
      "mode": "Deep"
    }
  ],
  "honeypot_sessions": [
    {
      "id": 1,
      "src_ip": "192.168.1.100",
      "username": "root",
      "auth_success": "failed"
    }
  ]
}
```

**Errors:**
- `400` - No IP provided
- `404` - Node not found

---

## Error Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad Request - Missing or invalid parameters |
| 404 | Not Found - Resource does not exist |
| 500 | Internal Server Error - Server-side error |
| 501 | Not Implemented - Feature not available |

---

## Rate Limiting

Currently, there is no built-in rate limiting. For production deployments, it is recommended to implement rate limiting at the reverse proxy level (e.g., nginx).

---

## Authentication

The API does not currently require authentication. For production deployments, it is strongly recommended to:

1. Deploy behind a reverse proxy with authentication
2. Use network-level access controls
3. Implement API key or token-based authentication

---

## Examples

### cURL Examples

**Locate an IP:**
```bash
curl "http://localhost:5000/api/v1/locate?ip=8.8.8.8"
```

**Perform a deep trace:**
```bash
curl "http://localhost:5000/api/v1/trace?ip=8.8.8.8&deep=1&maxttl=30"
```

**Search nodes:**
```bash
curl "http://localhost:5000/api/v1/search?type=node&q=google&fuzzy=1"
```

**Ingest Cowrie logs:**
```bash
curl -X POST "http://localhost:5000/api/v1/honeypot/ingest" \
  -H "Content-Type: application/json" \
  -d '{"path": "/data/honeypot/log/cowrie.json"}'
```

**Download artifact:**
```bash
curl -O "http://localhost:5000/api/v1/honeypot/artifact?name=malware.sh"
```

### Python Examples

```python
import requests

BASE_URL = "http://localhost:5000"

# Locate an IP
resp = requests.get(f"{BASE_URL}/api/v1/locate", params={"ip": "8.8.8.8"})
data = resp.json()
print(f"Country: {data['node']['country']}")

# Search for organizations
resp = requests.get(f"{BASE_URL}/api/v1/search", params={
    "type": "org",
    "q": "Google",
    "fuzzy": "1"
})
orgs = resp.json()["results"]

# List honeypot sessions
resp = requests.get(f"{BASE_URL}/api/v1/honeypot/sessions", params={"limit": 10})
sessions = resp.json()["sessions"]
for s in sessions:
    print(f"Session from {s['src_ip']}: {s['auth_success']}")
```

### JavaScript Examples

```javascript
// Using fetch API
async function locateIP(ip) {
    const response = await fetch(`/api/v1/locate?ip=${encodeURIComponent(ip)}`);
    if (!response.ok) throw new Error('Location failed');
    return await response.json();
}

// Usage
locateIP('8.8.8.8')
    .then(data => console.log(data.node.country))
    .catch(err => console.error(err));
```
