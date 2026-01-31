#!/usr/bin/env python3
"""
IOC Enricher - Offline-friendly threat intelligence enrichment tool
"""

import argparse
import sys
import logging
from typing import List, Dict
from parsers import IOCParser
from validators import IOCValidator
from taggers import IOCTagger
from exporters import JSONExporter, CSVExporter


class IOCEnricher:
    """Main class for IOC enrichment pipeline"""
    
    def __init__(self, dedupe=True, verbose=False):
        self.parser = IOCParser()
        self.validator = IOCValidator()
        self.tagger = IOCTagger()
        self.dedupe = dedupe
        self.verbose = verbose
        
        # Setup logging
        log_level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def process(self, input_data: str) -> List[Dict]:
        """
        Process raw input data through the enrichment pipeline
        
        Args:
            input_data: Raw text containing IOCs
            
        Returns:
            List of enriched IOC dictionaries
        """
        self.logger.info("Starting IOC enrichment pipeline")
        
        # Step 1: Parse and extract IOCs
        self.logger.debug("Parsing IOCs from input")
        raw_iocs = self.parser.extract_all(input_data)
        self.logger.info(f"Extracted {len(raw_iocs)} raw IOCs")
        
        # Step 2: Validate and normalize
        self.logger.debug("Validating and normalizing IOCs")
        validated_iocs = []
        for ioc_data in raw_iocs:
            if self.validator.is_valid(ioc_data['value'], ioc_data['type']):
                normalized = self.validator.normalize(ioc_data['value'], ioc_data['type'])
                validated_iocs.append({
                    'original': ioc_data['value'],
                    'normalized': normalized,
                    'type': ioc_data['type']
                })
        self.logger.info(f"Validated {len(validated_iocs)} IOCs")
        
        # Step 3: Deduplicate
        if self.dedupe:
            self.logger.debug("Deduplicating IOCs")
            validated_iocs = self._deduplicate(validated_iocs)
            self.logger.info(f"After deduplication: {len(validated_iocs)} unique IOCs")
        
        # Step 4: Tag with threat intelligence
        self.logger.debug("Applying threat intelligence tags")
        enriched_iocs = []
        for ioc_data in validated_iocs:
            tags = self.tagger.tag(ioc_data['normalized'], ioc_data['type'])
            enriched_iocs.append({
                'ioc': ioc_data['normalized'],
                'type': ioc_data['type'],
                'tags': tags,
                'normalized': ioc_data['normalized']
            })
        
        self.logger.info(f"Enrichment complete: {len(enriched_iocs)} IOCs processed")
        return enriched_iocs
    
    def _deduplicate(self, iocs: List[Dict]) -> List[Dict]:
        """Remove duplicate IOCs based on normalized value"""
        seen = set()
        unique_iocs = []
        for ioc in iocs:
            key = f"{ioc['type']}:{ioc['normalized']}"
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)
        return unique_iocs


def main():
    """Main entry point for CLI"""
    parser = argparse.ArgumentParser(
        description='IOC Enricher - Process and enrich indicators of compromise'
    )
    parser.add_argument(
        'input',
        nargs='?',
        type=argparse.FileType('r'),
        default=sys.stdin,
        help='Input file containing IOCs (default: stdin)'
    )
    parser.add_argument(
        '-o', '--output',
        type=argparse.FileType('w'),
        default=sys.stdout,
        help='Output file (default: stdout)'
    )
    parser.add_argument(
        '--format',
        choices=['json', 'csv'],
        default='json',
        help='Output format (default: json)'
    )
    parser.add_argument(
        '--no-dedupe',
        action='store_true',
        help='Disable deduplication'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Read input
    input_data = args.input.read()
    
    # Process IOCs
    enricher = IOCEnricher(dedupe=not args.no_dedupe, verbose=args.verbose)
    enriched_iocs = enricher.process(input_data)
    
    # Export results
    if args.format == 'json':
        exporter = JSONExporter()
    else:
        exporter = CSVExporter()
    
    output = exporter.export(enriched_iocs)
    args.output.write(output)
    
    # Print summary to stderr if not outputting to stdout
    if args.output != sys.stdout:
        print(f"Processed {len(enriched_iocs)} IOCs", file=sys.stderr)


if __name__ == '__main__':
    main()
