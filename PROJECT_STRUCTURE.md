# IOC Enricher - Project Structure

```
ioc-enricher/
│
├── README.md                    # Main documentation
├── SETUP.md                     # Installation and setup guide
├── CONTRIBUTING.md              # Contribution guidelines
├── LICENSE                      # MIT License
├── requirements.txt             # Python dependencies
├── .gitignore                   # Git ignore rules
│
├── ioc_enricher.py             # Main entry point (CLI)
├── parsers.py                  # IOC extraction logic
├── validators.py               # IOC validation and normalization
├── taggers.py                  # Threat intelligence tagging
├── exporters.py                # Output format handlers
│
├── quick_start.sh              # Quick demo script
│
├── examples/                   # Example files
│   ├── sample_input.txt        # Sample IOCs for testing
│   └── sample_output.json      # Example enriched output
│
└── tests/                      # Unit tests
    ├── test_parsers.py         # Parser tests
    ├── test_validators.py      # Validator tests
    └── test_taggers.py         # Tagger tests
```

## Core Components

### Main Script
- **ioc_enricher.py**: Command-line interface and orchestration

### Modules
- **parsers.py**: Regex-based extraction of various IOC types
- **validators.py**: Format validation and normalization
- **taggers.py**: Intelligence tagging based on characteristics
- **exporters.py**: JSON, CSV, SIEM, and STIX export formats

### Tests
- **test_parsers.py**: Tests for IOC extraction
- **test_validators.py**: Tests for validation logic
- **test_taggers.py**: Tests for tagging rules

## Data Flow

```
Input Text
    ↓
[Parser] → Extract IOCs (regex patterns)
    ↓
[Validator] → Validate & normalize format
    ↓
[Deduplicator] → Remove duplicates
    ↓
[Tagger] → Apply threat intelligence tags
    ↓
[Exporter] → Format output (JSON/CSV)
    ↓
Output
```

## Module Dependencies

```
ioc_enricher.py
    ├── parsers.py
    ├── validators.py
    ├── taggers.py
    │   └── validators.py (for helper functions)
    └── exporters.py
```

## Supported IOC Types

| Type | Module | Example |
|------|--------|---------|
| IPv4 | parsers.py | 192.168.1.1 |
| IPv6 | parsers.py | 2001:0db8::1 |
| Domain | parsers.py | malicious.com |
| URL | parsers.py | http://evil.com/payload |
| MD5 | parsers.py | 5d41402abc4b... |
| SHA1 | parsers.py | a94a8fe5ccb1... |
| SHA256 | parsers.py | e3b0c44298fc... |
| Email | parsers.py | attacker@evil.com |

## Tag Categories

### IP Tags
- private_ip, public_ip, rfc1918
- loopback, multicast, reserved, link_local

### Domain Tags
- suspicious_tld, known_tld, uncommon_tld
- long_domain, many_subdomains
- contains_numbers, contains_hyphen
- potential_dga

### URL Tags
- url_defanged
- suspicious_path
- ip_based_url

### Hash Tags
- hash_md5, hash_sha1, hash_sha256
- weak_hash

### Pattern Tags
- suspicious_pattern
- keyword_* (e.g., keyword_malware)

## Export Formats

### JSON
```json
{
  "ioc": "192.168.1.1",
  "type": "ipv4",
  "tags": ["private_ip", "rfc1918"],
  "normalized": "192.168.1.1"
}
```

### CSV
```csv
ioc,type,tags,normalized
192.168.1.1,ipv4,"private_ip,rfc1918",192.168.1.1
```

### SIEM (JSON)
```json
{
  "event_type": "ioc_indicator",
  "indicator": "192.168.1.1",
  "indicator_type": "ipv4",
  "threat_tags": ["private_ip"],
  "confidence": "low"
}
```

### STIX 2.1 (JSON)
STIX bundle with indicator objects

## Extension Points

### Adding New IOC Types
1. Add regex pattern to `parsers.py`
2. Add validation logic to `validators.py`
3. Add tagging rules to `taggers.py`
4. Add tests

### Adding New Tags
Edit `taggers.py` and add logic to appropriate `_tag_*` methods

### Adding Export Formats
1. Create new exporter class in `exporters.py`
2. Inherit from `BaseExporter`
3. Implement `export()` method
4. Update CLI in `ioc_enricher.py`

## Future Enhancements

- [ ] API integration (VirusTotal, AbuseIPDB, AlienVault OTX)
- [ ] Database storage (SQLite, PostgreSQL)
- [ ] Web interface (Flask/Django)
- [ ] Real-time streaming mode
- [ ] Machine learning-based scoring
- [ ] Historical tracking and trending
- [ ] Automated reporting
- [ ] Integration with SIEM platforms
- [ ] Docker containerization
- [ ] REST API endpoint
