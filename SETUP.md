# IOC Enricher Setup Guide

This guide will help you set up and start using the IOC Enricher tool.

## Prerequisites

- Python 3.7 or higher
- pip (Python package installer)
- Git (for cloning the repository)

## Installation

### Option 1: Clone from GitHub

```bash
# Clone the repository
git clone https://github.com/yourusername/ioc-enricher.git
cd ioc-enricher

# Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Option 2: Download ZIP

1. Download the ZIP file from GitHub
2. Extract to your desired location
3. Open terminal/command prompt in that directory
4. Run: `pip install -r requirements.txt`

## Quick Start

### 1. Run the Demo Script

```bash
chmod +x quick_start.sh
./quick_start.sh
```

### 2. Basic Usage

```bash
# Process a file
python3 ioc_enricher.py input.txt

# Save to file
python3 ioc_enricher.py input.txt -o output.json

# Use CSV format
python3 ioc_enricher.py input.txt -o output.csv --format csv

# Read from stdin
cat iocs.txt | python3 ioc_enricher.py
```

### 3. Try the Examples

```bash
# Process the sample input file
python3 ioc_enricher.py examples/sample_input.txt

# Generate CSV output
python3 ioc_enricher.py examples/sample_input.txt --format csv
```

## Verifying Installation

Run the tests to ensure everything is working:

```bash
# Install pytest if needed
pip install pytest

# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=. --cov-report=html
```

## Common Issues

### Issue: "ModuleNotFoundError"
**Solution**: Make sure you're in the correct directory and have installed requirements:
```bash
pip install -r requirements.txt
```

### Issue: "Permission denied" when running scripts
**Solution**: Make scripts executable:
```bash
chmod +x ioc_enricher.py quick_start.sh
```

### Issue: Python version too old
**Solution**: Install Python 3.7 or higher:
- Ubuntu/Debian: `sudo apt-get install python3.9`
- macOS: `brew install python3`
- Windows: Download from python.org

## Next Steps

1. **Customize tagging rules**: Edit `taggers.py` to add your own rules
2. **Add new IOC types**: Follow the guide in `CONTRIBUTING.md`
3. **Integrate with your workflow**: Use as a preprocessing step in your security pipeline
4. **Explore API options**: Add API integrations for threat intelligence enrichment

## Configuration

Currently, the tool works out-of-the-box with no configuration needed. Future versions may include:
- Config file for custom rules
- API key management
- Database connections
- Custom output templates

## Getting Help

- Check the main README.md for usage examples
- Review test files in `tests/` for code examples
- Open an issue on GitHub for bugs or questions
- See CONTRIBUTING.md for development guidelines

## Uninstallation

```bash
# Deactivate virtual environment
deactivate

# Remove the directory
cd ..
rm -rf ioc-enricher
```

Happy hunting! 🔍
