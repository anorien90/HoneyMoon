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

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Honeypot Setup](#honeypot-setup)
- [Architecture](#architecture)
- [Development](#development)
- [License](#license)

## Installation

### Prerequisites

- Python 3.9+
- Docker & Docker Compose (optional, for honeypot deployment)
- nmap (optional, for deep scanning)

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

The included `docker-compose.yml` sets up a Cowrie honeypot for testing:

```bash
# Set required environment variables
export HOST_SSH_PORT=2222
export COWRIE_PORT=2222

# Start the honeypot
docker compose up -d
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

### Data Sources

HoneyMoon enriches IP data from multiple sources:

- **GeoLite2** - IP geolocation (MaxMind)
- **RDAP** - Regional Internet Registry data
- **WHOIS** - Domain and IP registration data
- **ip-api.com** - Fallback geolocation API
- **OpenCorporates** - Company registry lookups
- **Tor Exit List** - Tor exit node detection

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