# IOC Enricher (Offline-friendly)

A command-line tool for enriching Indicators of Compromise (IOCs) with threat intelligence context. Process lists of IPs, domains, and hashes with normalization, deduplication, tagging, and export capabilities.

## Features

- **IOC Parsing & Validation**: Extract and validate IPs, domains, URLs, and file hashes using regex and format checks
- **Normalization & Deduplication**: Clean and standardize IOCs, removing duplicates
- **Threat Intelligence Tagging**: Apply contextual tags like "private IP", "known TLD", "suspicious patterns"
- **Multiple Export Formats**: Output to CSV or JSON for SIEM ingestion
- **Offline-friendly**: Core functionality works without API calls (optional API integration available)

## Installation

```bash
# Clone the repository
git clone https://github.com/nateng1/ioc-enricher.git
cd ioc-enricher

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
# Process a file containing IOCs
python ioc_enricher.py input.txt -o output.json

# Specify output format
python ioc_enricher.py input.txt -o output.csv --format csv

# Read from stdin
cat iocs.txt | python ioc_enricher.py --format json
```

### Input Format

The tool accepts plain text files with IOCs (one per line or mixed):

```
192.168.1.1
malicious-domain.com
http://example.evil/payload.exe
5d41402abc4b2a76b9719d911017c592
```

### Output Examples

**JSON Format:**
```json
[
  {
    "ioc": "192.168.1.1",
    "type": "ipv4",
    "tags": ["private_ip", "rfc1918"],
    "normalized": "192.168.1.1"
  },
  {
    "ioc": "malicious-domain.com",
    "type": "domain",
    "tags": ["suspicious_tld"],
    "normalized": "malicious-domain.com"
  }
]
```

**CSV Format:**
```csv
ioc,type,tags,normalized
192.168.1.1,ipv4,"private_ip,rfc1918",192.168.1.1
malicious-domain.com,domain,suspicious_tld,malicious-domain.com
```

## Tagging Rules

The tool applies the following tags automatically:

| Tag | Description |
|-----|-------------|
| `private_ip` | RFC1918 private address space |
| `known_tld` | Recognized top-level domain |
| `suspicious_tld` | TLD commonly associated with malicious activity |
| `suspicious_pattern` | Contains keywords like "malware", "evil", "phish" |
| `url_defanged` | URL has been defanged (hxxp, [.]) |
| `hash_md5` | MD5 file hash |
| `hash_sha1` | SHA1 file hash |
| `hash_sha256` | SHA256 file hash |

## Command-line Options

```
usage: ioc_enricher.py [-h] [-o OUTPUT] [--format {json,csv}] [--no-dedupe] 
                       [--verbose] [input]

positional arguments:
  input                 Input file containing IOCs (default: stdin)

optional arguments:
  -h, --help            Show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output file (default: stdout)
  --format {json,csv}   Output format (default: json)
  --no-dedupe           Disable deduplication
  --verbose             Enable verbose logging
```

## Project Structure

```
ioc-enricher/
├── README.md
├── requirements.txt
├── ioc_enricher.py       # Main script
├── parsers.py            # IOC extraction logic
├── validators.py         # IOC validation rules
├── taggers.py            # Tagging rules engine
├── exporters.py          # Output format handlers
├── tests/
│   ├── test_parsers.py
│   ├── test_validators.py
│   └── test_taggers.py
└── examples/
    ├── sample_input.txt
    └── sample_output.json
```

## Development

### Running Tests

```bash
pytest tests/
```

### Adding Custom Tags

Edit `taggers.py` to add custom tagging rules:

```python
def custom_tagger(ioc, ioc_type):
    tags = []
    if "mycustom" in ioc:
        tags.append("custom_pattern")
    return tags
```

## Future Enhancements

- [ ] API integration (VirusTotal, AbuseIPDB, etc.)
- [ ] Confidence scoring
- [ ] Historical tracking
- [ ] Batch processing optimization
- [ ] Web interface

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see LICENSE file for details

## Author

Your Name (@yourusername)
