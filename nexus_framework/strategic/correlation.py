"""
Correlation Engine - Multi-Tool Output Normalization

Advanced correlation and normalization of security tool outputs.
XML/JSON parsing, deduplication, cross-validation, confidence scoring.
Anomaly detection and inconsistency identification.

Features:
- Structured parsing of multiple tool formats
- Output normalization to unified schema
- Cross-tool result correlation
- Confidence scoring algorithms
- Anomaly detection
- Inconsistency identification
"""

import asyncio
import json
import logging
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import hashlib
import difflib
from collections import defaultdict, Counter
import numpy as np


class OutputFormat(Enum):
    """Supported tool output formats."""
    JSON = "json"
    XML = "xml"
    CSV = "csv"
    PLAIN_TEXT = "plain_text"
    NMAP_XML = "nmap_xml"
    NESSUS_XML = "nessus_xml"
    METASPLOIT_JSON = "metasploit_json"
    BURP_XML = "burp_xml"


class ConfidenceLevel(Enum):
    """Confidence levels for correlated results."""
    VERY_LOW = 0.1
    LOW = 0.3
    MEDIUM = 0.5
    HIGH = 0.7
    VERY_HIGH = 0.9


@dataclass
class NormalizedResult:
    """Normalized security finding."""
    finding_id: str
    tool_name: str
    timestamp: datetime
    target: str
    finding_type: str  # vulnerability, service, user, etc.
    severity: float  # 0-1
    confidence: float  # 0-1
    description: str
    raw_output: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    related_findings: List[str] = field(default_factory=list)
    validation_status: str = "unvalidated"  # validated, disputed, confirmed
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'finding_id': self.finding_id,
            'tool_name': self.tool_name,
            'timestamp': self.timestamp.isoformat(),
            'target': self.target,
            'finding_type': self.finding_type,
            'severity': self.severity,
            'confidence': self.confidence,
            'description': self.description,
            'raw_output': self.raw_output,
            'metadata': self.metadata,
            'related_findings': self.related_findings,
            'validation_status': self.validation_status
        }


@dataclass
class CorrelationResult:
    """Correlation analysis result."""
    correlation_id: str
    primary_findings: List[str]  # Finding IDs
    correlation_type: str  # duplicate, confirmation, contradiction
    confidence_score: float
    consensus_severity: Optional[float]
    consensus_description: str
    conflicting_tools: List[str] = field(default_factory=list)
    supporting_tools: List[str] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class OutputParser:
    """Parse various tool output formats."""
    
    def __init__(self):
        self.parsers = {
            OutputFormat.JSON: self._parse_json,
            OutputFormat.XML: self._parse_xml,
            OutputFormat.NMAP_XML: self._parse_nmap_xml,
            OutputFormat.NESSUS_XML: self._parse_nessus_xml,
            OutputFormat.METASPLOIT_JSON: self._parse_metasploit_json,
            OutputFormat.BURP_XML: self._parse_burp_xml,
            OutputFormat.CSV: self._parse_csv,
            OutputFormat.PLAIN_TEXT: self._parse_plain_text
        }
    
    def parse(self, output: str, format: OutputFormat, tool_name: str) -> List[Dict[str, Any]]:
        """Parse tool output based on format."""
        if format not in self.parsers:
            raise ValueError(f"Unsupported format: {format}")
        
        try:
            return self.parsers[format](output, tool_name)
        except Exception as e:
            logging.error(f"Failed to parse {format} output from {tool_name}: {e}")
            return []
    
    def _parse_json(self, output: str, tool_name: str) -> List[Dict[str, Any]]:
        """Parse JSON output."""
        try:
            data = json.loads(output)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                return [data]
            else:
                return []
        except json.JSONDecodeError as e:
            logging.error(f"JSON parsing failed for {tool_name}: {e}")
            return []
    
    def _parse_xml(self, output: str, tool_name: str) -> List[Dict[str, Any]]:
        """Parse generic XML output."""
        try:
            root = ET.fromstring(output)
            results = []
            
            # Try to extract common patterns
            for elem in root.iter():
                if len(elem) > 0:  # Has children
                    elem_dict = self._xml_element_to_dict(elem)
                    results.append(elem_dict)
            
            return results
        except ET.ParseError as e:
            logging.error(f"XML parsing failed for {tool_name}: {e}")
            return []
    
    def _parse_nmap_xml(self, output: str, tool_name: str) -> List[Dict[str, Any]]:
        """Parse Nmap XML output."""
        try:
            root = ET.fromstring(output)
            results = []
            
            for host in root.findall('.//host'):
                host_info = {
                    'tool': tool_name,
                    'type': 'host_discovery',
                    'ip': '',
                    'hostname': '',
                    'status': '',
                    'ports': [],
                    'os': '',
                    'scripts': []
                }
                
                # IP address
                address = host.find('.//address[@addrtype="ipv4"]')
                if address is not None:
                    host_info['ip'] = address.get('addr', '')
                
                # Hostname
                hostname = host.find('.//hostname')
                if hostname is not None:
                    host_info['hostname'] = hostname.get('name', '')
                
                # Status
                status = host.find('.//status')
                if status is not None:
                    host_info['status'] = status.get('state', '')
                
                # Ports
                for port in host.findall('.//port'):
                    port_info = {
                        'port': int(port.get('portid', 0)),
                        'protocol': port.get('protocol', ''),
                        'state': '',
                        'service': '',
                        'version': '',
                        'scripts': []
                    }
                    
                    state = port.find('.//state')
                    if state is not None:
                        port_info['state'] = state.get('state', '')
                    
                    service = port.find('.//service')
                    if service is not None:
                        port_info['service'] = service.get('name', '')
                        port_info['version'] = service.get('version', '')
                    
                    # Scripts
                    for script in port.findall('.//script'):
                        script_info = {
                            'id': script.get('id', ''),
                            'output': script.get('output', '')
                        }
                        port_info['scripts'].append(script_info)
                    
                    host_info['ports'].append(port_info)
                
                results.append(host_info)
            
            return results
        except ET.ParseError as e:
            logging.error(f"Nmap XML parsing failed: {e}")
            return []
    
    def _parse_nessus_xml(self, output: str, tool_name: str) -> List[Dict[str, Any]]:
        """Parse Nessus XML output."""
        try:
            root = ET.fromstring(output)
            results = []
            
            for report_item in root.findall('.//ReportItem'):
                item = {
                    'tool': tool_name,
                    'type': 'vulnerability',
                    'plugin_id': report_item.get('pluginID', ''),
                    'plugin_name': report_item.get('pluginName', ''),
                    'severity': self._nessus_severity_to_float(report_item.get('severity', '0')),
                    'host': '',
                    'port': '',
                    'protocol': '',
                    'description': '',
                    'solution': '',
                    'cve': [],
                    'cvss': {}
                }
                
                # Host and port
                host = report_item.find('.//host')
                if host is not None:
                    item['host'] = host.text or ''
                
                port = report_item.find('.//port')
                if port is not None:
                    item['port'] = port.text or ''
                
                # Description and solution
                description = report_item.find('.//description')
                if description is not None:
                    item['description'] = description.text or ''
                
                solution = report_item.find('.//solution')
                if solution is not None:
                    item['solution'] = solution.text or ''
                
                # CVE
                for cve in report_item.findall('.//cve'):
                    if cve.text:
                        item['cve'].append(cve.text)
                
                # CVSS
                cvss_base = report_item.find('.//cvss_base_score')
                if cvss_base is not None and cvss_base.text:
                    try:
                        item['cvss']['base'] = float(cvss_base.text)
                    except ValueError:
                        pass
                
                results.append(item)
            
            return results
        except ET.ParseError as e:
            logging.error(f"Nessus XML parsing failed: {e}")
            return []
    
    def _parse_metasploit_json(self, output: str, tool_name: str) -> List[Dict[str, Any]]:
        """Parse Metasploit JSON output."""
        try:
            data = json.loads(output)
            results = []
            
            if isinstance(data, dict):
                # Single result
                results.append(self._normalize_metasploit_result(data, tool_name))
            elif isinstance(data, list):
                # Multiple results
                for item in data:
                    results.append(self._normalize_metasploit_result(item, tool_name))
            
            return results
        except (json.JSONDecodeError, Exception) as e:
            logging.error(f"Metasploit JSON parsing failed: {e}")
            return []
    
    def _parse_burp_xml(self, output: str, tool_name: str) -> List[Dict[str, Any]]:
        """Parse Burp Suite XML output."""
        try:
            root = ET.fromstring(output)
            results = []
            
            for issue in root.findall('.//issue'):
                item = {
                    'tool': tool_name,
                    'type': 'web_vulnerability',
                    'name': '',
                    'severity': '',
                    'confidence': '',
                    'host': '',
                    'port': '',
                    'protocol': '',
                    'path': '',
                    'description': '',
                    'remediation': '',
                    'references': []
                }
                
                # Extract issue details
                name = issue.find('.//name')
                if name is not None and name.text:
                    item['name'] = name.text
                
                severity = issue.find('.//severity')
                if severity is not None and severity.text:
                    item['severity'] = severity.text
                
                confidence = issue.find('.//confidence')
                if confidence is not None and confidence.text:
                    item['confidence'] = confidence.text
                
                # Host information
                host = issue.find('.//host')
                if host is not None and host.text:
                    item['host'] = host.text
                
                port = issue.find('.//port')
                if port is not None and port.text:
                    item['port'] = port.text
                
                # Description and remediation
                description = issue.find('.//issueBackground')
                if description is not None and description.text:
                    item['description'] = description.text
                
                remediation = issue.find('.//remediationBackground')
                if remediation is not None and remediation.text:
                    item['remediation'] = remediation.text
                
                results.append(item)
            
            return results
        except ET.ParseError as e:
            logging.error(f"Burp XML parsing failed: {e}")
            return []
    
    def _parse_csv(self, output: str, tool_name: str) -> List[Dict[str, Any]]:
        """Parse CSV output."""
        try:
            import csv
            import io
            
            reader = csv.DictReader(io.StringIO(output))
            results = []
            
            for row in reader:
                # Add tool name and normalize
                row['tool'] = tool_name
                results.append(dict(row))
            
            return results
        except Exception as e:
            logging.error(f"CSV parsing failed for {tool_name}: {e}")
            return []
    
    def _parse_plain_text(self, output: str, tool_name: str) -> List[Dict[str, Any]]:
        """Parse plain text output using patterns."""
        results = []
        
        # Common patterns for different tools
        patterns = {
            'nmap': [
                r'(\d+\.\d+\.\d+\.\d+)\s+.*\s+(\w+)\s+open\s+(\w+)(?:\s+(.+))?',
                r'Nmap scan report for ([^\s]+) \((\d+\.\d+\.\d+\.\d+)\)'
            ],
            'nikto': [
                r'(\w+):\s+(https?://[^\s]+):\s+(.+)'
            ],
            'sslscan': [
                r'(\d+\.\d+\.\d+\.\d+):(\d+):\s+(.+)'
            ],
            'hydra': [
                r'\[(\d+)\]\[(\w+)\]\s+host:\s+(\d+\.\d+\.\d+\.\d+)\s+login:\s+(\w+)\s+password:\s+(.+)'
            ]
        }
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Try patterns for this tool
            tool_patterns = patterns.get(tool_name.lower(), [])
            for pattern in tool_patterns:
                match = re.match(pattern, line)
                if match:
                    result = {
                        'tool': tool_name,
                        'raw_line': line,
                        'matches': match.groups()
                    }
                    results.append(result)
                    break
            else:
                # No pattern matched, store as generic
                results.append({
                    'tool': tool_name,
                    'raw_line': line,
                    'type': 'unparsed'
                })
        
        return results
    
    def _xml_element_to_dict(self, elem: ET.Element) -> Dict[str, Any]:
        """Convert XML element to dictionary."""
        result = {}
        
        # Element attributes
        if elem.attrib:
            result.update(elem.attrib)
        
        # Element text
        if elem.text and elem.text.strip():
            if len(elem) == 0:  # No children
                return elem.text.strip()
            result['text'] = elem.text.strip()
        
        # Children
        for child in elem:
            child_data = self._xml_element_to_dict(child)
            if child.tag in result:
                if not isinstance(result[child.tag], list):
                    result[child.tag] = [result[child.tag]]
                result[child.tag].append(child_data)
            else:
                result[child.tag] = child_data
        
        return result
    
    def _nessus_severity_to_float(self, severity_str: str) -> float:
        """Convert Nessus severity to 0-1 scale."""
        severity_map = {
            '0': 0.0,  # Info
            '1': 0.2,  # Low
            '2': 0.4,  # Medium
            '3': 0.7,  # High
            '4': 1.0   # Critical
        }
        return severity_map.get(severity_str, 0.0)
    
    def _normalize_metasploit_result(self, data: Dict, tool_name: str) -> Dict[str, Any]:
        """Normalize Metasploit result."""
        return {
            'tool': tool_name,
            'type': 'exploit_result',
            'module': data.get('module', ''),
            'target': data.get('target', ''),
            'status': data.get('status', ''),
            'result': data.get('result', ''),
            'payload': data.get('payload', ''),
            'timestamp': data.get('timestamp', datetime.now().isoformat())
        }


class NormalizationEngine:
    """Normalize parsed outputs to unified schema."""
    
    def __init__(self):
        self.logger = logging.getLogger("normalization_engine")
    
    def normalize(self, parsed_data: List[Dict[str, Any]], tool_name: str, 
                 target: str = "") -> List[NormalizedResult]:
        """Normalize parsed data to unified schema."""
        normalized_results = []
        
        for item in parsed_data:
            try:
                result = self._normalize_item(item, tool_name, target)
                if result:
                    normalized_results.append(result)
            except Exception as e:
                self.logger.error(f"Normalization failed for item from {tool_name}: {e}")
        
        return normalized_results
    
    def _normalize_item(self, item: Dict[str, Any], tool_name: str, target: str) -> Optional[NormalizedResult]:
        """Normalize individual item."""
        # Generate unique finding ID
        finding_id = self._generate_finding_id(item, tool_name)
        
        # Extract common fields
        finding_type = self._extract_finding_type(item)
        severity = self._extract_severity(item)
        confidence = self._extract_confidence(item)
        description = self._extract_description(item)
        
        # Use provided target or extract from item
        extracted_target = target or self._extract_target(item)
        
        result = NormalizedResult(
            finding_id=finding_id,
            tool_name=tool_name,
            timestamp=datetime.now(),
            target=extracted_target,
            finding_type=finding_type,
            severity=severity,
            confidence=confidence,
            description=description,
            raw_output=json.dumps(item, default=str),
            metadata=item
        )
        
        return result
    
    def _generate_finding_id(self, item: Dict[str, Any], tool_name: str) -> str:
        """Generate unique finding ID."""
        # Create hash from key fields
        key_fields = []
        
        # Common key fields
        for field in ['ip', 'host', 'target', 'port', 'plugin_id', 'name']:
            if field in item and item[field]:
                key_fields.append(str(item[field]))
        
        # Add tool name
        key_fields.append(tool_name)
        
        # Generate hash
        content = '|'.join(key_fields)
        hash_obj = hashlib.md5(content.encode())
        return f"{tool_name}_{hash_obj.hexdigest()[:12]}"
    
    def _extract_finding_type(self, item: Dict[str, Any]) -> str:
        """Extract finding type from item."""
        type_mapping = {
            'vulnerability': 'vulnerability',
            'web_vulnerability': 'vulnerability',
            'host_discovery': 'host',
            'service': 'service',
            'port': 'service',
            'user': 'credential',
            'credential': 'credential',
            'exploit_result': 'exploit',
            'unparsed': 'unknown'
        }
        
        item_type = item.get('type', 'unknown')
        return type_mapping.get(item_type, item_type)
    
    def _extract_severity(self, item: Dict[str, Any]) -> float:
        """Extract severity (0-1) from item."""
        severity_fields = ['severity', 'cvss_base', 'risk', 'danger']
        
        for field in severity_fields:
            if field in item:
                try:
                    severity = float(item[field])
                    # Normalize to 0-1
                    if severity > 10:  # CVSS scores
                        return min(severity / 10, 1.0)
                    elif severity <= 1:  # Already normalized
                        return severity
                    else:  # 0-10 scale
                        return severity / 10
                except (ValueError, TypeError):
                    continue
        
        # Text-based severity
        text_severity = item.get('severity', '').lower()
        severity_map = {
            'info': 0.1,
            'low': 0.3,
            'medium': 0.5,
            'high': 0.7,
            'critical': 0.9,
            'very_high': 0.9
        }
        
        return severity_map.get(text_severity, 0.5)
    
    def _extract_confidence(self, item: Dict[str, Any]) -> float:
        """Extract confidence (0-1) from item."""
        confidence_fields = ['confidence', 'reliability', 'certainty']
        
        for field in confidence_fields:
            if field in item:
                try:
                    confidence = float(item[field])
                    return min(max(confidence, 0.0), 1.0)
                except (ValueError, TypeError):
                    continue
        
        # Text-based confidence
        text_confidence = item.get('confidence', '').lower()
        confidence_map = {
            'certain': 0.9,
            'firm': 0.7,
            'tentative': 0.5,
            'doubtful': 0.3
        }
        
        return confidence_map.get(text_confidence, 0.5)
    
    def _extract_description(self, item: Dict[str, Any]) -> str:
        """Extract description from item."""
        description_fields = ['description', 'name', 'plugin_name', 'issueBackground', 'text']
        
        for field in description_fields:
            if field in item and item[field]:
                return str(item[field])[:500]  # Limit length
        
        # Fallback to raw line
        if 'raw_line' in item:
            return item['raw_line'][:200]
        
        return "No description available"
    
    def _extract_target(self, item: Dict[str, Any]) -> str:
        """Extract target from item."""
        target_fields = ['target', 'host', 'ip', 'hostname']
        
        for field in target_fields:
            if field in item and item[field]:
                return str(item[field])
        
        return "unknown"


class CorrelationEngine:
    """Main correlation engine."""
    
    def __init__(self):
        self.parser = OutputParser()
        self.normalizer = NormalizationEngine()
        self.logger = logging.getLogger("correlation_engine")
        
        # Correlation cache
        self.correlation_cache: Dict[str, CorrelationResult] = {}
        self.finding_index: Dict[str, NormalizedResult] = {}
        
        # Similarity thresholds
        self.similarity_thresholds = {
            'exact_match': 0.95,
            'high_similarity': 0.8,
            'medium_similarity': 0.6,
            'low_similarity': 0.4
        }
    
    async def process_tool_output(self, output: str, format: OutputFormat, 
                                tool_name: str, target: str = "") -> List[NormalizedResult]:
        """Process tool output through parsing and normalization."""
        # Parse output
        parsed_data = self.parser.parse(output, format, tool_name)
        
        # Normalize
        normalized_results = self.normalizer.normalize(parsed_data, tool_name, target)
        
        # Index findings
        for result in normalized_results:
            self.finding_index[result.finding_id] = result
        
        self.logger.info(f"Processed {len(normalized_results)} results from {tool_name}")
        return normalized_results
    
    async def correlate_findings(self, findings: List[NormalizedResult]) -> List[CorrelationResult]:
        """Correlate findings across tools."""
        correlations = []
        
        # Group findings by target
        target_groups = defaultdict(list)
        for finding in findings:
            target_groups[finding.target].append(finding)
        
        # Correlate within each target group
        for target, target_findings in target_groups.items():
            target_correlations = await self._correlate_target_findings(target_findings)
            correlations.extend(target_correlations)
        
        # Update cache
        for correlation in correlations:
            self.correlation_cache[correlation.correlation_id] = correlation
        
        return correlations
    
    async def _correlate_target_findings(self, findings: List[NormalizedResult]) -> List[CorrelationResult]:
        """Correlate findings for a specific target."""
        correlations = []
        
        # Find duplicates
        duplicates = self._find_duplicates(findings)
        for duplicate_group in duplicates:
            correlation = self._create_duplicate_correlation(duplicate_group)
            correlations.append(correlation)
        
        # Find confirmations
        confirmations = self._find_confirmations(findings)
        for confirmation_group in confirmations:
            correlation = self._create_confirmation_correlation(confirmation_group)
            correlations.append(correlation)
        
        # Find contradictions
        contradictions = self._find_contradictions(findings)
        for contradiction_group in contradictions:
            correlation = self._create_contradiction_correlation(contradiction_group)
            correlations.append(correlation)
        
        return correlations
    
    def _find_duplicates(self, findings: List[NormalizedResult]) -> List[List[NormalizedResult]]:
        """Find duplicate findings across tools."""
        duplicates = []
        processed = set()
        
        for i, finding1 in enumerate(findings):
            if finding1.finding_id in processed:
                continue
            
            duplicate_group = [finding1]
            processed.add(finding1.finding_id)
            
            for j, finding2 in enumerate(findings[i+1:], i+1):
                if finding2.finding_id in processed:
                    continue
                
                similarity = self._calculate_similarity(finding1, finding2)
                if similarity >= self.similarity_thresholds['exact_match']:
                    duplicate_group.append(finding2)
                    processed.add(finding2.finding_id)
            
            if len(duplicate_group) > 1:
                duplicates.append(duplicate_group)
        
        return duplicates
    
    def _find_confirmations(self, findings: List[NormalizedResult]) -> List[List[NormalizedResult]]:
        """Find findings that confirm each other."""
        confirmations = []
        processed = set()
        
        for i, finding1 in enumerate(findings):
            if finding1.finding_id in processed:
                continue
            
            confirmation_group = [finding1]
            processed.add(finding1.finding_id)
            
            for j, finding2 in enumerate(findings[i+1:], i+1):
                if finding2.finding_id in processed:
                    continue
                
                if self._are_confirmations(finding1, finding2):
                    confirmation_group.append(finding2)
                    processed.add(finding2.finding_id)
            
            if len(confirmation_group) > 1:
                confirmations.append(confirmation_group)
        
        return confirmations
    
    def _find_contradictions(self, findings: List[NormalizedResult]) -> List[List[NormalizedResult]]:
        """Find contradictory findings."""
        contradictions = []
        processed = set()
        
        for i, finding1 in enumerate(findings):
            if finding1.finding_id in processed:
                continue
            
            contradiction_group = [finding1]
            processed.add(finding1.finding_id)
            
            for j, finding2 in enumerate(findings[i+1:], i+1):
                if finding2.finding_id in processed:
                    continue
                
                if self._are_contradictions(finding1, finding2):
                    contradiction_group.append(finding2)
                    processed.add(finding2.finding_id)
            
            if len(contradiction_group) > 1:
                contradictions.append(contradiction_group)
        
        return contradictions
    
    def _calculate_similarity(self, finding1: NormalizedResult, finding2: NormalizedResult) -> float:
        """Calculate similarity between two findings."""
        similarity_scores = []
        
        # Target similarity
        if finding1.target == finding2.target:
            similarity_scores.append(1.0)
        else:
            similarity_scores.append(0.0)
        
        # Type similarity
        if finding1.finding_type == finding2.finding_type:
            similarity_scores.append(1.0)
        else:
            similarity_scores.append(0.0)
        
        # Description similarity
        desc_similarity = difflib.SequenceMatcher(None, finding1.description, finding2.description).ratio()
        similarity_scores.append(desc_similarity)
        
        # Severity similarity
        severity_diff = abs(finding1.severity - finding2.severity)
        severity_similarity = 1.0 - severity_diff
        similarity_scores.append(severity_similarity)
        
        # Weighted average
        weights = [0.3, 0.2, 0.3, 0.2]  # target, type, description, severity
        weighted_sum = sum(score * weight for score, weight in zip(similarity_scores, weights))
        
        return weighted_sum
    
    def _are_confirmations(self, finding1: NormalizedResult, finding2: NormalizedResult) -> bool:
        """Check if two findings confirm each other."""
        # Same target and type, similar severity
        if (finding1.target == finding2.target and 
            finding1.finding_type == finding2.finding_type and
            abs(finding1.severity - finding2.severity) < 0.2):
            return True
        
        # High description similarity
        desc_similarity = difflib.SequenceMatcher(None, finding1.description, finding2.description).ratio()
        if desc_similarity > self.similarity_thresholds['high_similarity']:
            return True
        
        return False
    
    def _are_contradictions(self, finding1: NormalizedResult, finding2: NormalizedResult) -> bool:
        """Check if two findings contradict each other."""
        # Same target but opposite findings
        if finding1.target == finding2.target:
            # Port open vs closed
            if ('open' in finding1.description.lower() and 'closed' in finding2.description.lower()) or \
               ('closed' in finding1.description.lower() and 'open' in finding2.description.lower()):
                return True
            
            # Vulnerable vs secure
            if ('vulnerable' in finding1.description.lower() and 'secure' in finding2.description.lower()) or \
               ('secure' in finding1.description.lower() and 'vulnerable' in finding2.description.lower()):
                return True
        
        return False
    
    def _create_duplicate_correlation(self, duplicate_group: List[NormalizedResult]) -> CorrelationResult:
        """Create correlation result for duplicates."""
        finding_ids = [f.finding_id for f in duplicate_group]
        tools = list(set(f.tool_name for f in duplicate_group))
        
        # Calculate consensus
        severities = [f.severity for f in duplicate_group]
        consensus_severity = sum(severities) / len(severities)
        
        # Use description from highest confidence finding
        highest_confidence_finding = max(duplicate_group, key=lambda f: f.confidence)
        
        correlation_id = f"dup_{hashlib.md5('|'.join(sorted(finding_ids)).encode()).hexdigest()[:8]}"
        
        return CorrelationResult(
            correlation_id=correlation_id,
            primary_findings=finding_ids,
            correlation_type="duplicate",
            confidence_score=0.9,
            consensus_severity=consensus_severity,
            consensus_description=highest_confidence_finding.description,
            supporting_tools=tools,
            metadata={'duplicate_count': len(duplicate_group)}
        )
    
    def _create_confirmation_correlation(self, confirmation_group: List[NormalizedResult]) -> CorrelationResult:
        """Create correlation result for confirmations."""
        finding_ids = [f.finding_id for f in confirmation_group]
        tools = list(set(f.tool_name for f in confirmation_group))
        
        # Calculate consensus
        severities = [f.severity for f in confirmation_group]
        consensus_severity = sum(severities) / len(severities)
        
        # Combine descriptions
        descriptions = [f.description for f in confirmation_group]
        consensus_description = " | ".join(descriptions[:3])  # Limit length
        
        correlation_id = f"conf_{hashlib.md5('|'.join(sorted(finding_ids)).encode()).hexdigest()[:8]}"
        
        return CorrelationResult(
            correlation_id=correlation_id,
            primary_findings=finding_ids,
            correlation_type="confirmation",
            confidence_score=0.8,
            consensus_severity=consensus_severity,
            consensus_description=consensus_description,
            supporting_tools=tools,
            metadata={'confirmation_count': len(confirmation_group)}
        )
    
    def _create_contradiction_correlation(self, contradiction_group: List[NormalizedResult]) -> CorrelationResult:
        """Create correlation result for contradictions."""
        finding_ids = [f.finding_id for f in contradiction_group]
        tools = list(set(f.tool_name for f in contradiction_group))
        
        correlation_id = f"contra_{hashlib.md5('|'.join(sorted(finding_ids)).encode()).hexdigest()[:8]}"
        
        return CorrelationResult(
            correlation_id=correlation_id,
            primary_findings=finding_ids,
            correlation_type="contradiction",
            confidence_score=0.7,
            consensus_severity=None,  # No consensus due to contradiction
            consensus_description="Contradictory findings detected",
            conflicting_tools=tools,
            anomalies=['severity_mismatch', 'description_conflict'],
            metadata={'contradiction_count': len(contradiction_group)}
        )
    
    def detect_anomalies(self, findings: List[NormalizedResult]) -> List[str]:
        """Detect anomalies in findings."""
        anomalies = []
        
        # Statistical anomalies
        if len(findings) > 5:
            severities = [f.severity for f in findings]
            mean_severity = sum(severities) / len(severities)
            std_severity = np.std(severities)
            
            # Find outliers
            for finding in findings:
                z_score = abs(finding.severity - mean_severity) / std_severity if std_severity > 0 else 0
                if z_score > 2.0:  # 2 standard deviations
                    anomalies.append(f"severity_outlier_{finding.finding_id}")
        
        # Temporal anomalies
        timestamps = [f.timestamp for f in findings]
        if len(timestamps) > 1:
            time_span = max(timestamps) - min(timestamps)
            if time_span > timedelta(days=7):
                anomalies.append("extended_time_span")
        
        # Tool consistency anomalies
        tool_counts = Counter(f.tool_name for f in findings)
        if len(tool_counts) == 1:
            anomalies.append("single_tool_only")
        
        return anomalies
    
    def get_correlation_summary(self) -> Dict[str, Any]:
        """Get summary of correlation analysis."""
        total_correlations = len(self.correlation_cache)
        
        correlation_types = Counter(c.correlation_type for c in self.correlation_cache.values())
        
        confidence_scores = [c.confidence_score for c in self.correlation_cache.values()]
        avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0
        
        return {
            'total_correlations': total_correlations,
            'correlation_types': dict(correlation_types),
            'average_confidence': avg_confidence,
            'findings_indexed': len(self.finding_index),
            'last_updated': datetime.now().isoformat()
        }
