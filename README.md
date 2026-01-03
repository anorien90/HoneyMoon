# HoneyMoon

<p align="center">
  <img src="static/media/LogoPlain.png" alt="HoneyMoon Logo" width="120">
</p>

**HoneyMoon** is a comprehensive network forensics and honeypot analysis platform designed for security professionals. It provides real-time monitoring, IP geolocation, traceroute analysis, and automated ingestion of honeypot logs (Cowrie) and network captures (PCAP).

## Features

- **🗺️ IP Geolocation & Mapping** - Visualize network nodes on an interactive map using Leaflet with GeoLite2 database integration
- **🔍 Network Traceroute** - Perform traceroute analysis with deep mode for service fingerprinting
- **🍯 Honeypot Integration** - Automated ingestion and analysis of Cowrie honeypot logs
- **📊 Database Explorer** - Search and browse network nodes, organizations, sessions, and web accesses
- **🔐 TLS/SSL Analysis** - Certificate inspection and cipher suite analysis
- **📡 PCAP Analysis** - Ingest and analyze network captures for flow data
- **🏢 Organization Intelligence** - RDAP/WHOIS lookups with company registry enrichment
- **📋 Web Access Logging** - Nginx JSON log ingestion and correlation with network intelligence
- **🤖 AI-Powered Threat Analysis** - Local IBM Granite LLM integration via Ollama for session analysis and threat extraction
- **🔎 Similarity Search** - Vector embeddings with Qdrant for finding similar attacks and attackers
- **🎯 Counter-Measure Planning** - LLM-generated countermeasure recommendations
- **📦 Attacker Clustering** - Automatic grouping of related attacks and threat actors

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [AI Analysis Setup](#ai-analysis-setup)
- [Honeypot Setup](#honeypot-setup)
- [Architecture](#architecture)
- [Development](#development)
- [License](#license)

## Installation

### Prerequisites

- Python 3.9+
- Docker & Docker Compose (optional, for honeypot deployment)
- nmap (optional, for deep scanning)
- Ollama (optional, for AI threat analysis)
- Qdrant (optional, for similarity search)

### Using pip

```bash
# Clone the repository
git clone https://github.com/anorien90/HoneyMoon.git
cd HoneyMoon

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python -m src.app
```

### Using Docker Compose

The included `docker-compose.yml` sets up a Cowrie honeypot, Qdrant vector database, and Ollama LLM:

```bash
# Set required environment variables
export HOST_SSH_PORT=2222
export COWRIE_PORT=2222

# Start the honeypot and Qdrant (default services)
docker compose up -d

# Start with AI services (Ollama for LLM analysis)
docker compose --profile ai up -d

# After starting, pull the Granite model for AI analysis
docker exec embedding ollama pull granite3.1-dense:8b
```

## Quick Start

1. **Start the server:**
   ```bash
   python -m src.app
   ```

2. **Access the web interface:**
   Open your browser to `http://localhost:5000`

3. **Locate an IP:**
   Enter an IP address and click "Locate" to see geolocation data on the map.

4. **Trace a route:**
   Enter a target IP and click "Trace" to visualize the network path.

5. **Enable Deep Mode:**
   Check the "Deep" checkbox before tracing to enable service fingerprinting and banner grabbing.

## Configuration

HoneyMoon is configured through environment variables:

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `IPMAP_PORT` | `5000` | HTTP server port |
| `IPMAP_DEBUG` | `1` | Enable debug mode |
| `IPMAP_TEMPLATES` | `./templates` | Template directory path |
| `IPMAP_STATIC` | `./static` | Static files directory path |

### Database Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SQLITE_BUSY_TIMEOUT_SECONDS` | `30` | SQLite busy timeout |

### GeoLite Database

| Variable | Default | Description |
|----------|---------|-------------|
| `GEOLITE_MMDB_PATH` | `./data/GeoLite2-City.mmdb` | Path to GeoLite2 database |
| `GEOLITE_MMDB_URL` | MaxMind URL | URL to download GeoLite2 database |

### Honeypot Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `HONEY_AUTO_INGEST` | `true` | Enable automatic log ingestion |
| `HONEY_LOG_PATH` | `./data/honeypot/log/cowrie.json` | Path to Cowrie JSON log |
| `HONEY_DATA_DIR` | `./data/honeypot` | Honeypot data directory |
| `HONEY_INGEST_INTERVAL` | `30` | Log polling interval (seconds) |

### Nginx Access Log Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `NGINX_AUTO_INGEST` | `true` | Enable automatic nginx log ingestion |
| `NGINX_LOG_PATH` | `./data/access.json` | Path to nginx JSON access log |
| `NGINX_INGEST_INTERVAL` | `30` | Log polling interval (seconds) |

### AI Analysis Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_ENABLED` | `true` | Enable LLM-based threat analysis |
| `LLM_MODEL` | `granite3.1-dense:8b` | Ollama model to use for analysis |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama server URL |
| `VECTOR_STORE_ENABLED` | `true` | Enable vector similarity search |
| `QDRANT_USE_LOCAL` | `true` | Use local Qdrant storage (vs remote server) |
| `QDRANT_PATH` | `./data/qdrant` | Path for local Qdrant data |
| `QDRANT_HOST` | `localhost` | Qdrant server host (if not local) |
| `QDRANT_PORT` | `6333` | Qdrant server port |
| `EMBEDDING_MODEL` | `all-MiniLM-L6-v2` | Sentence transformer model for embeddings |

## AI Analysis Setup

HoneyMoon includes AI-powered threat analysis using local IBM Granite models and vector similarity search.

### Option 1: Using Docker Compose (Recommended)

The included `docker-compose.yml` provides an Ollama service for AI analysis:

1. **Start the Ollama container with the AI profile:**
   ```bash
   # Start Ollama and Qdrant services
   docker compose --profile ai up -d
   ```

2. **Pull the Granite model inside the container:**
   ```bash
   # Pull the recommended model
   docker exec embedding ollama pull granite3.1-dense:8b
   ```

3. **Verify Ollama is running:**
   ```bash
   # Check available models
   docker exec embedding ollama list
   
   # Test the API
   curl http://localhost:11434/api/tags
   ```

> **Note:** The Ollama container is configured with GPU support. If you don't have a GPU, edit `docker-compose.yml` and remove the `deploy.resources.reservations.devices` section from the `embedding` service:
>
> ```yaml
> # Remove this section from the embedding service if you don't have a GPU:
> deploy:
>   resources:
>     reservations:
>       devices:
>         - driver: nvidia
>           count: all
>           capabilities: [gpu]
> ```

### Option 2: Installing Ollama Locally

1. **Install Ollama:**
   ```bash
   # Linux
   curl -fsSL https://ollama.com/install.sh | sh
   
   # macOS
   brew install ollama
   ```

2. **Start Ollama:**
   ```bash
   ollama serve
   ```

3. **Pull the Granite model:**
   ```bash
   ollama pull granite3.1-dense:8b
   ```

### Troubleshooting Ollama

If you see the warning `No supported LLM model found`, ensure that:

1. The Ollama service is running and accessible at `http://localhost:11434`
2. The Granite model has been pulled (run `ollama list` or `docker exec embedding ollama list` to check)
3. The `OLLAMA_HOST` environment variable is set correctly if using a non-default host

```bash
# Check Ollama status
curl http://localhost:11434/api/tags

# Pull the model if missing (local installation)
ollama pull granite3.1-dense:8b

# Pull the model if missing (Docker - use the 'embedding' container name from docker-compose.yml)
docker exec embedding ollama pull granite3.1-dense:8b
```

### Using AI Analysis

Once Ollama is running with Granite, the AI features are automatically available:

- **Session Analysis**: Analyze honeypot sessions for threat type, severity, and MITRE ATT&CK mapping
- **Counter-Measure Planning**: Get actionable recommendations to address identified threats
- **Artifact Examination**: Analyze captured malware and scripts
- **Threat Unification**: Create unified threat profiles from multiple related sessions

### Example: Analyzing a Session

```bash
# Analyze a honeypot session
curl -X POST http://localhost:5000/api/v1/llm/analyze/session \
  -H "Content-Type: application/json" \
  -d '{"session_id": 1}'

# Get countermeasure recommendations
curl -X POST http://localhost:5000/api/v1/llm/countermeasure \
  -H "Content-Type: application/json" \
  -d '{"threat_analysis_id": 1}'
```

### Vector Similarity Search

The vector store enables finding similar attacks and attackers:

```bash
# Search for similar sessions
curl "http://localhost:5000/api/v1/vector/search/sessions?q=ssh+brute+force"

# Find similar attackers to a specific IP
curl "http://localhost:5000/api/v1/similar/attackers?ip=10.0.0.1"

# Create a cluster of related attacks
curl -X POST http://localhost:5000/api/v1/cluster \
  -H "Content-Type: application/json" \
  -d '{"session_ids": [1, 2, 3], "name": "SSH Botnet Campaign"}'
```

## API Reference

### Locate IP

Get geolocation and organization information for an IP address.

```http
GET /api/v1/locate?ip=<ip_address>
```

**Response:**
```json
{
  "node": {
    "ip": "8.8.8.8",
    "hostname": "dns.google",
    "organization": "Google LLC",
    "country": "United States",
    "city": "Mountain View",
    "latitude": 37.386,
    "longitude": -122.084,
    "asn": "AS15169",
    "is_tor_exit": false
  },
  "organization": {
    "id": 1,
    "name": "Google LLC",
    "rdap": {...}
  }
}
```

### Trace Route

Perform a traceroute to the target IP.

```http
GET /api/v1/trace?ip=<ip>&deep=<0|1>&maxttl=<int>
```

**Parameters:**
- `ip` - Target IP address
- `deep` - Enable deep scanning (0/1)
- `maxttl` - Maximum TTL (default: 30)

### Search

Search nodes or organizations.

```http
GET /api/v1/search?type=<node|org>&q=<query>&fuzzy=<0|1>&limit=<int>
```

### Database Search

Unified search across all database tables.

```http
GET /api/v1/db/search?type=<type>&q=<query>&limit=<int>
```

**Types:** `node`, `org`, `honeypot`, `access`, `analysis`, `flow`

### Honeypot Endpoints

#### List Sessions
```http
GET /api/v1/honeypot/sessions?limit=<int>
```

#### Get Session Details
```http
GET /api/v1/honeypot/session?id=<int>
```

#### Ingest Cowrie Logs
```http
POST /api/v1/honeypot/ingest
Content-Type: application/json

{"path": "/data/honeypot/cowrie.json"}
```

#### Ingest PCAP
```http
POST /api/v1/honeypot/ingest_pcap
Content-Type: application/json

{"path": "/data/honeypot/capture.pcap", "filter_host": "192.168.1.1"}
```

#### Download Artifact
```http
GET /api/v1/honeypot/artifact?name=<filename>
```

#### List Network Flows
```http
GET /api/v1/honeypot/flows?limit=<int>
```

### Organization Endpoints

#### Get Organization
```http
GET /api/v1/organization?ip=<ip>
GET /api/v1/organization?id=<org_id>
```

#### Refresh Organization Data
```http
GET /api/v1/organization/refresh?id=<ip_or_org_id>&force=<0|1>
```

### Web Access Endpoints

#### Get Accesses for IP
```http
GET /api/v1/accesses?ip=<ip>&limit=<int>
```

### Health Check

```http
GET /api/v1/health
```

### AI Analysis Endpoints

#### Get LLM Status
```http
GET /api/v1/llm/status
```

#### Analyze Honeypot Session
```http
POST /api/v1/llm/analyze/session
Content-Type: application/json

{"session_id": 1, "save": true}
```

**Response:**
```json
{
  "analyzed": true,
  "threat_type": "SSH Brute Force",
  "severity": "high",
  "confidence": 0.9,
  "summary": "Automated SSH brute force attack targeting root account...",
  "tactics": ["Initial Access", "Credential Access"],
  "techniques": ["T1110 - Brute Force"],
  "indicators": ["Multiple failed login attempts", "Common password list used"],
  "recommendations": ["Block source IP", "Implement fail2ban"]
}
```

#### Analyze Web Access Logs
```http
POST /api/v1/llm/analyze/accesses
Content-Type: application/json

{"ip": "10.0.0.1", "limit": 100, "save": true}
```

#### Analyze Connections
```http
POST /api/v1/llm/analyze/connections
Content-Type: application/json

{"direction": "outgoing", "limit": 100, "save": true}
```

#### Generate Countermeasure Plan
```http
POST /api/v1/llm/countermeasure
Content-Type: application/json

{"threat_analysis_id": 1, "context": {"source_ip": "10.0.0.1"}}
```

#### Examine Artifact
```http
POST /api/v1/llm/examine/artifact
Content-Type: application/json

{"artifact_name": "abc123_malware.sh"}
```

#### Unify Threat Profiles
```http
POST /api/v1/llm/unify
Content-Type: application/json

{"session_ids": [1, 2, 3]}
```

### Vector Search Endpoints

#### Get Vector Store Status
```http
GET /api/v1/vector/status
```

#### Index Session
```http
POST /api/v1/vector/index/session
Content-Type: application/json

{"session_id": 1}
```

#### Index Node
```http
POST /api/v1/vector/index/node
Content-Type: application/json

{"ip": "8.8.8.8"}
```

#### Search Similar Sessions
```http
GET /api/v1/vector/search/sessions?q=<query>&session_id=<id>&limit=<int>
```

#### Search Similar Nodes
```http
GET /api/v1/vector/search/nodes?q=<query>&ip=<ip>&limit=<int>
```

#### Search Similar Threats
```http
GET /api/v1/vector/search/threats?q=<query>&limit=<int>
```

### Threat Analysis Endpoints

#### List Threats
```http
GET /api/v1/threats?type=<session|access|connection>&limit=<int>
```

#### Get Threat
```http
GET /api/v1/threat?id=<int>
```

### Cluster Endpoints

#### List Clusters
```http
GET /api/v1/clusters?limit=<int>
```

#### Get or Create Cluster
```http
GET /api/v1/cluster?id=<int>

POST /api/v1/cluster
Content-Type: application/json

{"session_ids": [1, 2, 3], "name": "Campaign Name"}
```

#### Find Similar Attackers
```http
GET /api/v1/similar/attackers?ip=<ip>&threshold=<float>&limit=<int>
```

## Honeypot Setup

### Cowrie Integration

HoneyMoon automatically ingests Cowrie JSON logs when configured:

1. **Configure Cowrie** to output JSON logs:
   ```ini
   [output_jsonlog]
   enabled = true
   logfile = ${honeypot:data_dir}/log/cowrie.json
   ```

2. **Set environment variables:**
   ```bash
   export HONEY_AUTO_INGEST=true
   export HONEY_LOG_PATH=/path/to/cowrie.json
   ```

3. **Using Docker Compose:**
   
   The included `docker-compose.yml` mounts the appropriate directories:
   ```yaml
   volumes:
     - ./data/honeypot/log:/cowrie/cowrie-git/var/log/cowrie/:rw
     - ./data/honeypot/data:/data/cowrie/:rw
   ```

### Manual Ingestion

You can also manually ingest logs:

```bash
# Using the CLI script
python -m src.ingest_cowrie_structured /path/to/cowrie.json

# Using the API
curl -X POST http://localhost:5000/api/v1/honeypot/ingest \
  -H "Content-Type: application/json" \
  -d '{"path": "/data/honeypot/log/cowrie.json"}'
```

### PCAP Ingestion

```bash
# Using the CLI script
python -m src.pcap_ingest /path/to/capture.pcap

# Using the API
curl -X POST http://localhost:5000/api/v1/honeypot/ingest_pcap \
  -H "Content-Type: application/json" \
  -d '{"path": "/data/honeypot/capture.pcap"}'
```

## Architecture

### Directory Structure

```
HoneyMoon/
├── src/
│   ├── app.py                 # Flask application and API routes
│   ├── entry.py               # SQLAlchemy models (NetworkNode, Organization, etc.)
│   ├── forensic_engine.py     # Core analysis engine
│   ├── forensic_extension.py  # Service fingerprinting helpers
│   ├── honeypot_models.py     # Honeypot-related models
│   ├── vector_store.py        # Qdrant vector storage for similarity search
│   ├── llm_analyzer.py        # IBM Granite LLM integration via Ollama
│   ├── ingest_cowrie_structured.py  # Cowrie log ingestion CLI
│   └── pcap_ingest.py         # PCAP ingestion CLI
├── templates/
│   └── index.html             # Main web interface
├── static/
│   ├── app.js                 # Main application JavaScript
│   ├── api.js                 # API client
│   ├── map.js                 # Leaflet map integration
│   ├── ui.js                  # UI components
│   ├── honeypot-ui.js         # Honeypot panel UI
│   ├── db-ui.js               # Database explorer UI
│   └── styles.css             # Application styles
├── data/                      # Data files (gitignored)
│   └── qdrant/                # Qdrant vector database storage
├── docker-compose.yml         # Honeypot deployment
├── requirements.txt           # Python dependencies
└── README.md
```

### Database Models

- **NetworkNode** - IP addresses with geolocation and organization data
- **Organization** - Company/ISP information with RDAP data
- **AnalysisSession** - Traceroute session records
- **PathHop** - Individual hops in a traceroute
- **WebAccess** - Nginx access log entries
- **HoneypotSession** - Cowrie session records
- **HoneypotCommand** - Commands executed in honeypot sessions
- **HoneypotFile** - Files downloaded/uploaded in honeypot sessions
- **HoneypotNetworkFlow** - Network flow data from PCAP analysis
- **ThreatAnalysis** - LLM-generated threat analyses with MITRE ATT&CK mapping
- **AttackerCluster** - Clusters of related attackers/campaigns

### Data Sources

HoneyMoon enriches IP data from multiple sources:

- **GeoLite2** - IP geolocation (MaxMind)
- **RDAP** - Regional Internet Registry data
- **WHOIS** - Domain and IP registration data
- **ip-api.com** - Fallback geolocation API
- **OpenCorporates** - Company registry lookups
- **Tor Exit List** - Tor exit node detection
- **IBM Granite LLM** - Local AI threat analysis (via Ollama)
- **Qdrant** - Vector similarity search for attack correlation

## Development

### Running Tests

```bash
# Install test dependencies
pip install pytest

# Run tests
pytest
```

### Code Style

The project uses standard Python conventions. Please ensure your code:

- Follows PEP 8 guidelines
- Includes docstrings for public functions
- Handles exceptions appropriately

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security Considerations

- **⚠️ Scanning Permission** - Only scan systems you own or have explicit permission to scan
- **🔒 Production Deployment** - Disable debug mode and use proper authentication in production
- **🛡️ Path Traversal** - Artifact downloads are restricted to the artifacts directory
- **📁 Ingest Paths** - Log ingestion is restricted to the honeypot data directory

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Cowrie](https://github.com/cowrie/cowrie) - SSH/Telnet honeypot
- [Leaflet](https://leafletjs.com/) - Interactive maps
- [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) - IP geolocation database
- [Scapy](https://scapy.net/) - Packet manipulation
- [Flask](https://flask.palletsprojects.com/) - Web framework