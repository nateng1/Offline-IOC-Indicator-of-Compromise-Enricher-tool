#!/bin/bash
# Quick start script for IOC Enricher demo

echo "==================================="
echo "IOC Enricher - Quick Start Demo"
echo "==================================="
echo ""

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not found"
    exit 1
fi

echo "✓ Python 3 found"
echo ""

# Create a sample IOC file if it doesn't exist
if [ ! -f "demo_iocs.txt" ]; then
    echo "Creating demo IOC file..."
    cat > demo_iocs.txt << 'EOF'
192.168.1.100
malicious-domain.xyz
http://evil-site.tk/payload.exe
5d41402abc4b2a76b9719d911017c592
phishing@suspicious-site.xyz
hxxps://defanged-url[.]com
203.0.113.42
EOF
    echo "✓ Created demo_iocs.txt"
fi

echo ""
echo "Running IOC enricher..."
echo "Input file: demo_iocs.txt"
echo ""

# Run the enricher
python3 ioc_enricher.py demo_iocs.txt --format json --verbose

echo ""
echo "==================================="
echo "Demo complete!"
echo ""
echo "Try these commands:"
echo "  python3 ioc_enricher.py demo_iocs.txt --format csv"
echo "  python3 ioc_enricher.py examples/sample_input.txt"
echo "  cat demo_iocs.txt | python3 ioc_enricher.py"
echo ""
