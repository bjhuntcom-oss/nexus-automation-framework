"""
OPSEC & Safety Layer - Controlled Security Mechanisms

Controlled operational security layer focused on:
- Noise reduction and stealth optimization
- Scope enforcement and boundary protection
- Attribution protection (accidental)
- Intelligent throttling and rate limiting
- Environment inconsistency detection
- Honeypot awareness (defensive detection)
- Contractual compliance framework

This is NOT for illegal evasion but for controlled, authorized testing.
"""

import asyncio
import json
import logging
import re
import time
import random
import ipaddress
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from collections import defaultdict, deque
import hashlib
import statistics


class RiskLevel(Enum):
    """Risk assessment levels."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EXTREME = 5


class NoiseLevel(Enum):
    """Network noise levels."""
    SILENT = 1
    LOW = 2
    MODERATE = 3
    HIGH = 4
    EXTREME = 5


class ScopeViolationType(Enum):
    """Types of scope violations."""
    IP_OUT_OF_RANGE = "ip_out_of_range"
    DOMAIN_OUT_OF_SCOPE = "domain_out_of_scope"
    PORT_RESTRICTION = "port_restriction"
    PROTOCOL_RESTRICTION = "protocol_restriction"
    TIME_RESTRICTION = "time_restriction"
    TECHNIQUE_RESTRICTION = "technique_restriction"
    INTENSITY_LIMIT = "intensity_limit"


@dataclass
class ScopeDefinition:
    """Operational scope definition."""
    scope_id: str
    name: str
    authorized_targets: List[str]  # IP ranges, domains
    forbidden_targets: List[str]
    allowed_ports: Set[int]
    forbidden_ports: Set[int]
    allowed_protocols: Set[str]
    forbidden_protocols: Set[str]
    allowed_techniques: Set[str]
    forbidden_techniques: Set[str]
    time_windows: List[Tuple[datetime, datetime]]  # Start, end pairs
    max_concurrent_connections: int
    max_requests_per_minute: int
    stealth_requirement: float  # 0-1
    noise_tolerance: float  # 0-1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'scope_id': self.scope_id,
            'name': self.name,
            'authorized_targets': self.authorized_targets,
            'forbidden_targets': self.forbidden_targets,
            'allowed_ports': list(self.allowed_ports),
            'forbidden_ports': list(self.forbidden_ports),
            'allowed_protocols': list(self.allowed_protocols),
            'forbidden_protocols': list(self.forbidden_protocols),
            'allowed_techniques': list(self.allowed_techniques),
            'forbidden_techniques': list(self.forbidden_techniques),
            'time_windows': [(start.isoformat(), end.isoformat()) for start, end in self.time_windows],
            'max_concurrent_connections': self.max_concurrent_connections,
            'max_requests_per_minute': self.max_requests_per_minute,
            'stealth_requirement': self.stealth_requirement,
            'noise_tolerance': self.noise_tolerance
        }


@dataclass
class NoiseProfile:
    """Network noise profile for stealth analysis."""
    tool_name: str
    typical_noise_level: NoiseLevel
    signature_patterns: List[str]
    detection_indicators: List[str]
    mitigation_techniques: List[str]
    stealth_score: float  # 0-1
    time_between_requests: float  # seconds
    concurrent_connections: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'tool_name': self.tool_name,
            'typical_noise_level': self.typical_noise_level.value,
            'signature_patterns': self.signature_patterns,
            'detection_indicators': self.detection_indicators,
            'mitigation_techniques': self.mitigation_techniques,
            'stealth_score': self.stealth_score,
            'time_between_requests': self.time_between_requests,
            'concurrent_connections': self.concurrent_connections
        }


@dataclass
class OPSECViolation:
    """OPSEC violation record."""
    violation_id: str
    violation_type: ScopeViolationType
    severity: RiskLevel
    description: str
    tool_name: str
    target: str
    timestamp: datetime
    detected_by: str
    mitigated: bool = False
    mitigation_action: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'violation_id': self.violation_id,
            'violation_type': self.violation_type.value,
            'severity': self.severity.value,
            'description': self.description,
            'tool_name': self.tool_name,
            'target': self.target,
            'timestamp': self.timestamp.isoformat(),
            'detected_by': self.detected_by,
            'mitigated': self.mitigated,
            'mitigation_action': self.mitigation_action,
            'metadata': self.metadata
        }


class ScopeEnforcer:
    """Enforces operational scope boundaries."""
    
    def __init__(self):
        self.logger = logging.getLogger("scope_enforcer")
        self.scopes: Dict[str, ScopeDefinition] = {}
        self.ip_networks: Dict[str, List[ipaddress.IPv4Network]] = {}
        self.domain_patterns: Dict[str, List[re.Pattern]] = {}
        
        # Load default scope patterns
        self._load_default_patterns()
    
    def _load_default_patterns(self):
        """Load default scope patterns."""
        # Common honeypot indicators
        self.honeypot_patterns = [
            r'.*honeypot.*',
            r'.*trap.*',
            r'.*decoy.*',
            r'.*canary.*',
            r'.*tarpit.*'
        ]
        
        # High-risk services
        self.high_risk_ports = {22, 23, 53, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 6379}
        
        # Sensitive protocols
        self.sensitive_protocols = {'ssh', 'rdp', 'smb', 'ldap', 'mysql', 'postgresql'}
    
    def add_scope(self, scope: ScopeDefinition) -> bool:
        """Add a new scope definition."""
        try:
            # Pre-compile IP networks
            ip_networks = []
            for target in scope.authorized_targets:
                try:
                    if '/' in target:  # CIDR notation
                        network = ipaddress.IPv4Network(target, strict=False)
                        ip_networks.append(network)
                    else:  # Single IP
                        ip = ipaddress.IPv4Address(target)
                        network = ipaddress.IPv4Network(f"{ip}/32", strict=False)
                        ip_networks.append(network)
                except ipaddress.AddressValueError:
                    # Not an IP, might be a domain
                    pass
            
            # Pre-compile domain patterns
            domain_patterns = []
            for target in scope.authorized_targets:
                if not '/' in target and '.' in target:  # Likely a domain
                    try:
                        pattern = re.compile(target.replace('*', '.*'), re.IGNORECASE)
                        domain_patterns.append(pattern)
                    except re.error:
                        pass
            
            self.scopes[scope.scope_id] = scope
            self.ip_networks[scope.scope_id] = ip_networks
            self.domain_patterns[scope.scope_id] = domain_patterns
            
            self.logger.info(f"Added scope {scope.name} with {len(scope.authorized_targets)} targets")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add scope {scope.scope_id}: {e}")
            return False
    
    def check_target_scope(self, scope_id: str, target: str) -> Tuple[bool, Optional[ScopeViolationType]]:
        """Check if target is within scope."""
        if scope_id not in self.scopes:
            return False, ScopeViolationType.IP_OUT_OF_RANGE
        
        scope = self.scopes[scope_id]
        
        # Check forbidden targets first
        if self._matches_target(target, scope.forbidden_targets):
            return False, ScopeViolationType.IP_OUT_OF_RANGE
        
        # Check authorized targets
        if not self._matches_target(target, scope.authorized_targets):
            return False, ScopeViolationType.IP_OUT_OF_RANGE
        
        return True, None
    
    def check_port_scope(self, scope_id: str, port: int) -> Tuple[bool, Optional[ScopeViolationType]]:
        """Check if port is within scope."""
        if scope_id not in self.scopes:
            return False, ScopeViolationType.PORT_RESTRICTION
        
        scope = self.scopes[scope_id]
        
        # Check forbidden ports
        if port in scope.forbidden_ports:
            return False, ScopeViolationType.PORT_RESTRICTION
        
        # Check allowed ports (if specified)
        if scope.allowed_ports and port not in scope.allowed_ports:
            return False, ScopeViolationType.PORT_RESTRICTION
        
        return True, None
    
    def check_protocol_scope(self, scope_id: str, protocol: str) -> Tuple[bool, Optional[ScopeViolationType]]:
        """Check if protocol is within scope."""
        if scope_id not in self.scopes:
            return False, ScopeViolationType.PROTOCOL_RESTRICTION
        
        scope = self.scopes[scope_id]
        protocol = protocol.lower()
        
        # Check forbidden protocols
        if protocol in scope.forbidden_protocols:
            return False, ScopeViolationType.PROTOCOL_RESTRICTION
        
        # Check allowed protocols (if specified)
        if scope.allowed_protocols and protocol not in scope.allowed_protocols:
            return False, ScopeViolationType.PROTOCOL_RESTRICTION
        
        return True, None
    
    def check_time_scope(self, scope_id: str) -> Tuple[bool, Optional[ScopeViolationType]]:
        """Check if current time is within scope."""
        if scope_id not in self.scopes:
            return False, ScopeViolationType.TIME_RESTRICTION
        
        scope = self.scopes[scope_id]
        current_time = datetime.now()
        
        # Check time windows
        if scope.time_windows:
            in_window = any(
                start <= current_time <= end 
                for start, end in scope.time_windows
            )
            if not in_window:
                return False, ScopeViolationType.TIME_RESTRICTION
        
        return True, None
    
    def check_technique_scope(self, scope_id: str, technique: str) -> Tuple[bool, Optional[ScopeViolationType]]:
        """Check if technique is within scope."""
        if scope_id not in self.scopes:
            return False, ScopeViolationType.TECHNIQUE_RESTRICTION
        
        scope = self.scopes[scope_id]
        
        # Check forbidden techniques
        if technique in scope.forbidden_techniques:
            return False, ScopeViolationType.TECHNIQUE_RESTRICTION
        
        # Check allowed techniques (if specified)
        if scope.allowed_techniques and technique not in scope.allowed_techniques:
            return False, ScopeViolationType.TECHNIQUE_RESTRICTION
        
        return True, None
    
    def _matches_target(self, target: str, target_list: List[str]) -> bool:
        """Check if target matches any in the list."""
        for pattern in target_list:
            if self._target_matches_pattern(target, pattern):
                return True
        return False
    
    def _target_matches_pattern(self, target: str, pattern: str) -> bool:
        """Check if target matches a specific pattern."""
        try:
            # IP address matching
            if '/' in pattern:
                network = ipaddress.IPv4Network(pattern, strict=False)
                try:
                    ip = ipaddress.IPv4Address(target)
                    return ip in network
                except ipaddress.AddressValueError:
                    pass
            elif pattern.replace('.', '').replace('-', '').isdigit():
                # Simple IP match
                return target == pattern
            
            # Domain matching
            if '.' in pattern:
                regex_pattern = pattern.replace('*', '.*').replace('?', '.')
                return re.match(f"^{regex_pattern}$", target, re.IGNORECASE) is not None
            
            # Exact match
            return target == pattern
            
        except Exception:
            return False
    
    def detect_honeypot_indicators(self, target: str, service_info: Dict[str, Any]) -> List[str]:
        """Detect potential honeypot indicators."""
        indicators = []
        
        # Check service banners
        banner = service_info.get('banner', '').lower()
        for pattern in self.honeypot_patterns:
            if re.search(pattern, banner, re.IGNORECASE):
                indicators.append(f"Honeypot pattern in banner: {pattern}")
        
        # Check unusual service configurations
        if service_info.get('port') in self.high_risk_ports:
            indicators.append(f"High-risk port: {service_info.get('port')}")
        
        # Check for suspicious service versions
        version = service_info.get('version', '').lower()
        if any(keyword in version for keyword in ['honeypot', 'trap', 'decoy']):
            indicators.append(f"Suspicious version string: {version}")
        
        return indicators


class NoiseController:
    """Controls and reduces operational noise."""
    
    def __init__(self):
        self.logger = logging.getLogger("noise_controller")
        self.noise_profiles: Dict[str, NoiseProfile] = {}
        self.request_history: deque = deque(maxlen=1000)
        self.current_noise_level = NoiseLevel.MODERATE
        
        # Load default noise profiles
        self._load_noise_profiles()
    
    def _load_noise_profiles(self):
        """Load default tool noise profiles."""
        self.noise_profiles = {
            'nmap': NoiseProfile(
                tool_name='nmap',
                typical_noise_level=NoiseLevel.HIGH,
                signature_patterns=[
                    r'SYN scan',
                    r'UDP scan',
                    r'Version scan',
                    r'OS detection'
                ],
                detection_indicators=[
                    'Port scan detected',
                    'Multiple connection attempts',
                    'SYN flood pattern'
                ],
                mitigation_techniques=[
                    'Timing optimization',
                    'Source port randomization',
                    'Fragmented packets'
                ],
                stealth_score=0.3,
                time_between_requests=0.1,
                concurrent_connections=10
            ),
            'nikto': NoiseProfile(
                tool_name='nikto',
                typical_noise_level=NoiseLevel.HIGH,
                signature_patterns=[
                    r'Nikto',
                    r'OSVDB',
                    r'web vulnerability'
                ],
                detection_indicators=[
                    'Web vulnerability scan',
                    'HTTP enumeration',
                    'Directory traversal attempts'
                ],
                mitigation_techniques=[
                    'User-Agent rotation',
                    'Request timing variation',
                    'Header randomization'
                ],
                stealth_score=0.2,
                time_between_requests=0.5,
                concurrent_connections=5
            ),
            'hydra': NoiseProfile(
                tool_name='hydra',
                typical_noise_level=NoiseLevel.EXTREME,
                signature_patterns=[
                    r'brute force',
                    r'password',
                    r'login attempt'
                ],
                detection_indicators=[
                    'Brute force attack',
                    'Multiple failed logins',
                    'Account lockout'
                ],
                mitigation_techniques=[
                    'Credential rotation',
                    'Rate limiting',
                    'Source IP rotation'
                ],
                stealth_score=0.1,
                time_between_requests=1.0,
                concurrent_connections=3
            )
        }
    
    def calculate_noise_level(self, tool_name: str, target_count: int, 
                            request_rate: float) -> NoiseLevel:
        """Calculate current noise level."""
        profile = self.noise_profiles.get(tool_name)
        if not profile:
            return NoiseLevel.MODERATE
        
        # Base noise from tool profile
        base_noise = profile.typical_noise_level.value
        
        # Adjust for target count
        if target_count > 100:
            target_factor = 1.5
        elif target_count > 50:
            target_factor = 1.2
        else:
            target_factor = 1.0
        
        # Adjust for request rate
        if request_rate > profile.concurrent_connections * 2:
            rate_factor = 1.5
        elif request_rate > profile.concurrent_connections:
            rate_factor = 1.2
        else:
            rate_factor = 1.0
        
        # Calculate final noise level
        noise_score = base_noise * target_factor * rate_factor
        
        # Map to enum
        if noise_score <= 1.5:
            return NoiseLevel.SILENT
        elif noise_score <= 2.5:
            return NoiseLevel.LOW
        elif noise_score <= 3.5:
            return NoiseLevel.MODERATE
        elif noise_score <= 4.5:
            return NoiseLevel.HIGH
        else:
            return NoiseLevel.EXTREME
    
    def recommend_stealth_settings(self, tool_name: str, required_stealth: float) -> Dict[str, Any]:
        """Recommend stealth settings for tool."""
        profile = self.noise_profiles.get(tool_name)
        if not profile:
            return {}
        
        recommendations = {
            'tool_name': tool_name,
            'current_stealth_score': profile.stealth_score,
            'required_stealth': required_stealth,
            'recommendations': []
        }
        
        if required_stealth > profile.stealth_score:
            stealth_gap = required_stealth - profile.stealth_score
            
            if stealth_gap > 0.3:
                recommendations['recommendations'].extend([
                    'Increase timing delays significantly',
                    'Reduce concurrent connections',
                    'Use source IP rotation'
                ])
            elif stealth_gap > 0.1:
                recommendations['recommendations'].extend([
                    'Moderate timing delays',
                    'Reduce concurrent connections slightly'
                ])
            
            # Specific tool recommendations
            if tool_name == 'nmap':
                recommendations['recommendations'].append('Use -T2 or -T1 timing')
                recommendations['recommendations'].append('Enable -f for packet fragmentation')
                recommendations['recommendations'].append('Use -D for decoy scanning')
            
            elif tool_name == 'nikto':
                recommendations['recommendations'].append('Use -tuning 9 for stealth')
                recommendations['recommendations'].append('Increase -pause between requests')
            
            elif tool_name == 'hydra':
                recommendations['recommendations'].append('Reduce thread count')
                recommendations['recommendations'].append('Increase wait time')
                recommendations['recommendations'].append('Use proxy chains')
        
        return recommendations
    
    def track_request(self, tool_name: str, target: str, timestamp: datetime = None):
        """Track request for noise analysis."""
        if timestamp is None:
            timestamp = datetime.now()
        
        self.request_history.append({
            'tool': tool_name,
            'target': target,
            'timestamp': timestamp
        })
    
    def get_noise_statistics(self, time_window: timedelta = timedelta(minutes=5)) -> Dict[str, Any]:
        """Get noise statistics for time window."""
        cutoff_time = datetime.now() - time_window
        
        recent_requests = [
            req for req in self.request_history
            if req['timestamp'] > cutoff_time
        ]
        
        # Group by tool
        tool_stats = defaultdict(lambda: {'count': 0, 'targets': set()})
        for req in recent_requests:
            tool_stats[req['tool']]['count'] += 1
            tool_stats[req['tool']]['targets'].add(req['target'])
        
        # Calculate overall metrics
        total_requests = len(recent_requests)
        unique_targets = len(set(req['target'] for req in recent_requests))
        request_rate = total_requests / time_window.total_seconds() if time_window.total_seconds() > 0 else 0
        
        return {
            'time_window_minutes': time_window.total_seconds() / 60,
            'total_requests': total_requests,
            'unique_targets': unique_targets,
            'requests_per_second': request_rate,
            'tool_statistics': {
                tool: {
                    'request_count': stats['count'],
                    'unique_targets': len(stats['targets']),
                    'requests_per_second': stats['count'] / time_window.total_seconds() if time_window.total_seconds() > 0 else 0
                }
                for tool, stats in tool_stats.items()
            },
            'current_noise_level': self.current_noise_level.value
        }


class ThrottlingManager:
    """Manages request throttling and rate limiting."""
    
    def __init__(self):
        self.logger = logging.getLogger("throttling_manager")
        self.rate_limits: Dict[str, Dict[str, Any]] = {}
        self.request_buckets: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.global_limits = {
            'max_requests_per_second': 100,
            'max_concurrent_requests': 50
        }
    
    def set_rate_limit(self, identifier: str, max_requests: int, time_window: int):
        """Set rate limit for identifier."""
        self.rate_limits[identifier] = {
            'max_requests': max_requests,
            'time_window': time_window,
            'requests_per_second': max_requests / time_window
        }
    
    def check_rate_limit(self, identifier: str) -> Tuple[bool, float]:
        """Check if request is allowed under rate limit."""
        if identifier not in self.rate_limits:
            return True, 0.0
        
        limit = self.rate_limits[identifier]
        now = datetime.now()
        cutoff_time = now - timedelta(seconds=limit['time_window'])
        
        # Clean old requests
        bucket = self.request_buckets[identifier]
        while bucket and bucket[0] < cutoff_time:
            bucket.popleft()
        
        # Check limit
        current_count = len(bucket)
        if current_count >= limit['max_requests']:
            # Calculate wait time
            oldest_request = bucket[0] if bucket else now
            wait_time = (oldest_request + timedelta(seconds=limit['time_window'])) - now
            return False, max(0, wait_time.total_seconds())
        
        # Add current request
        bucket.append(now)
        return True, 0.0
    
    def calculate_adaptive_delay(self, tool_name: str, target_count: int, 
                               stealth_requirement: float) -> float:
        """Calculate adaptive delay based on stealth requirements."""
        base_delays = {
            'nmap': 0.1,
            'nikto': 0.5,
            'hydra': 1.0,
            'sqlmap': 2.0,
            'dirb': 0.3
        }
        
        base_delay = base_delays.get(tool_name, 0.5)
        
        # Adjust for stealth requirement
        stealth_multiplier = 1.0 + (stealth_requirement * 4.0)  # 1x to 5x
        
        # Adjust for target count
        if target_count > 1000:
            target_multiplier = 2.0
        elif target_count > 100:
            target_multiplier = 1.5
        else:
            target_multiplier = 1.0
        
        return base_delay * stealth_multiplier * target_multiplier


class OPSECManager:
    """Main OPSEC management system."""
    
    def __init__(self):
        self.logger = logging.getLogger("opsec_manager")
        self.scope_enforcer = ScopeEnforcer()
        self.noise_controller = NoiseController()
        self.throttling_manager = ThrottlingManager()
        
        # Violation tracking
        self.violations: List[OPSECViolation] = []
        self.violation_callbacks: List[Callable] = []
        
        # Configuration
        self.max_violations_per_hour = 10
        self.auto_mitigation_enabled = True
        
        # Statistics
        self.stats = {
            'total_violations': 0,
            'scope_violations': 0,
            'noise_violations': 0,
            'throttling_violations': 0,
            'mitigated_violations': 0
        }
    
    def add_scope(self, scope: ScopeDefinition) -> bool:
        """Add operational scope."""
        return self.scope_enforcer.add_scope(scope)
    
    def validate_operation(self, scope_id: str, tool_name: str, target: str, 
                          port: Optional[int] = None, protocol: Optional[str] = None,
                          technique: Optional[str] = None) -> Tuple[bool, List[OPSECViolation]]:
        """Validate operation against OPSEC rules."""
        violations = []
        
        # Check scope compliance
        target_valid, target_violation = self.scope_enforcer.check_target_scope(scope_id, target)
        if not target_valid:
            violation = OPSECViolation(
                violation_id=str(uuid.uuid4()),
                violation_type=target_violation,
                severity=RiskLevel.HIGH,
                description=f"Target {target} is outside authorized scope",
                tool_name=tool_name,
                target=target,
                timestamp=datetime.now(),
                detected_by="scope_enforcer"
            )
            violations.append(violation)
        
        # Check port scope
        if port:
            port_valid, port_violation = self.scope_enforcer.check_port_scope(scope_id, port)
            if not port_valid:
                violation = OPSECViolation(
                    violation_id=str(uuid.uuid4()),
                    violation_type=port_violation,
                    severity=RiskLevel.MEDIUM,
                    description=f"Port {port} is not authorized for scope",
                    tool_name=tool_name,
                    target=f"{target}:{port}",
                    timestamp=datetime.now(),
                    detected_by="scope_enforcer"
                )
                violations.append(violation)
        
        # Check protocol scope
        if protocol:
            protocol_valid, protocol_violation = self.scope_enforcer.check_protocol_scope(scope_id, protocol)
            if not protocol_valid:
                violation = OPSECViolation(
                    violation_id=str(uuid.uuid4()),
                    violation_type=protocol_violation,
                    severity=RiskLevel.MEDIUM,
                    description=f"Protocol {protocol} is not authorized for scope",
                    tool_name=tool_name,
                    target=f"{target} ({protocol})",
                    timestamp=datetime.now(),
                    detected_by="scope_enforcer"
                )
                violations.append(violation)
        
        # Check technique scope
        if technique:
            technique_valid, technique_violation = self.scope_enforcer.check_technique_scope(scope_id, technique)
            if not technique_valid:
                violation = OPSECViolation(
                    violation_id=str(uuid.uuid4()),
                    violation_type=technique_violation,
                    severity=RiskLevel.HIGH,
                    description=f"Technique {technique} is not authorized for scope",
                    tool_name=tool_name,
                    target=target,
                    timestamp=datetime.now(),
                    detected_by="scope_enforcer"
                )
                violations.append(violation)
        
        # Check time scope
        time_valid, time_violation = self.scope_enforcer.check_time_scope(scope_id)
        if not time_valid:
            violation = OPSECViolation(
                violation_id=str(uuid.uuid4()),
                violation_type=time_violation,
                severity=RiskLevel.MEDIUM,
                description="Operation is outside authorized time window",
                tool_name=tool_name,
                target=target,
                timestamp=datetime.now(),
                detected_by="scope_enforcer"
            )
            violations.append(violation)
        
        # Check rate limiting
        rate_limit_id = f"{scope_id}:{tool_name}"
        rate_allowed, wait_time = self.throttling_manager.check_rate_limit(rate_limit_id)
        if not rate_allowed:
            violation = OPSECViolation(
                violation_id=str(uuid.uuid4()),
                violation_type=ScopeViolationType.INTENSITY_LIMIT,
                severity=RiskLevel.MEDIUM,
                description=f"Rate limit exceeded. Wait {wait_time:.1f}s",
                tool_name=tool_name,
                target=target,
                timestamp=datetime.now(),
                detected_by="throttling_manager"
            )
            violations.append(violation)
        
        # Record violations
        for violation in violations:
            self._record_violation(violation)
        
        # Auto-mitigate if enabled
        if self.auto_mitigation_enabled and violations:
            self._auto_mitigate_violations(violations)
        
        return len(violations) == 0, violations
    
    def analyze_noise(self, tool_name: str, target_count: int, 
                     request_rate: float) -> Dict[str, Any]:
        """Analyze operational noise."""
        # Calculate noise level
        noise_level = self.noise_controller.calculate_noise_level(tool_name, target_count, request_rate)
        
        # Get stealth recommendations
        scope = self.scope_enforcer.scopes.get(list(self.scope_enforcer.scopes.keys())[0])  # Get first scope
        stealth_req = scope.stealth_requirement if scope else 0.5
        recommendations = self.noise_controller.recommend_stealth_settings(tool_name, stealth_req)
        
        # Get noise statistics
        stats = self.noise_controller.get_noise_statistics()
        
        return {
            'tool_name': tool_name,
            'target_count': target_count,
            'request_rate': request_rate,
            'current_noise_level': noise_level.value,
            'stealth_requirement': stealth_req,
            'recommendations': recommendations,
            'statistics': stats
        }
    
    def detect_environment_anomalies(self, target: str, service_info: Dict[str, Any]) -> List[str]:
        """Detect environmental anomalies and inconsistencies."""
        anomalies = []
        
        # Check for honeypot indicators
        honeypot_indicators = self.scope_enforcer.detect_honeypot_indicators(target, service_info)
        anomalies.extend(honeypot_indicators)
        
        # Check for unusual service configurations
        if service_info.get('port') and service_info.get('service'):
            # Common port-service mismatches
            port_service_mismatches = {
                22: 'ssh',
                80: 'http',
                443: 'https',
                3306: 'mysql',
                5432: 'postgresql'
            }
            
            expected_service = port_service_mismatches.get(service_info['port'])
            if expected_service and service_info['service'] != expected_service:
                anomalies.append(f"Unexpected service {service_info['service']} on port {service_info['port']}")
        
        # Check for suspicious version strings
        version = service_info.get('version', '')
        if any(suspicious in version.lower() for suspicious in ['test', 'demo', 'honeypot', 'trap']):
            anomalies.append(f"Suspicious version string: {version}")
        
        return anomalies
    
    def get_stealth_recommendations(self, tool_name: str, operation_context: Dict[str, Any]) -> Dict[str, Any]:
        """Get comprehensive stealth recommendations."""
        recommendations = {
            'tool_name': tool_name,
            'operation_context': operation_context,
            'recommendations': [],
            'risk_level': RiskLevel.LOW.value
        }
        
        # Get noise-based recommendations
        target_count = operation_context.get('target_count', 1)
        request_rate = operation_context.get('request_rate', 1.0)
        noise_analysis = self.analyze_noise(tool_name, target_count, request_rate)
        
        if 'recommendations' in noise_analysis:
            recommendations['recommendations'].extend(noise_analysis['recommendations']['recommendations'])
        
        # Calculate adaptive delay
        stealth_requirement = operation_context.get('stealth_requirement', 0.5)
        adaptive_delay = self.throttling_manager.calculate_adaptive_delay(
            tool_name, target_count, stealth_requirement
        )
        
        recommendations['recommendations'].append(f"Use adaptive delay: {adaptive_delay:.2f}s")
        
        # Determine overall risk level
        if noise_analysis['current_noise_level'] >= NoiseLevel.HIGH.value:
            recommendations['risk_level'] = RiskLevel.HIGH.value
        elif noise_analysis['current_noise_level'] >= NoiseLevel.MODERATE.value:
            recommendations['risk_level'] = RiskLevel.MEDIUM.value
        
        return recommendations
    
    def _record_violation(self, violation: OPSECViolation):
        """Record OPSEC violation."""
        self.violations.append(violation)
        self.stats['total_violations'] += 1
        
        # Update specific violation counters
        if 'scope' in violation.detected_by:
            self.stats['scope_violations'] += 1
        elif 'noise' in violation.detected_by:
            self.stats['noise_violations'] += 1
        elif 'throttling' in violation.detected_by:
            self.stats['throttling_violations'] += 1
        
        # Trigger callbacks
        for callback in self.violation_callbacks:
            try:
                callback(violation)
            except Exception as e:
                self.logger.error(f"Violation callback error: {e}")
    
    def _auto_mitigate_violations(self, violations: List[OPSECViolation]):
        """Automatically mitigate violations."""
        for violation in violations:
            if violation.mitigated:
                continue
            
            # Determine mitigation action based on violation type
            if violation.violation_type in [ScopeViolationType.IP_OUT_OF_RANGE, ScopeViolationType.DOMAIN_OUT_OF_SCOPE]:
                violation.mitigation_action = "Block target and alert operator"
                violation.mitigated = True
                self.stats['mitigated_violations'] += 1
            
            elif violation.violation_type == ScopeViolationType.INTENSITY_LIMIT:
                violation.mitigation_action = "Apply rate limiting"
                violation.mitigated = True
                self.stats['mitigated_violations'] += 1
            
            elif violation.severity.value >= RiskLevel.HIGH.value:
                violation.mitigation_action = "Pause operation and require manual approval"
                violation.mitigated = True
                self.stats['mitigated_violations'] += 1
    
    def get_opsec_summary(self) -> Dict[str, Any]:
        """Get OPSEC summary and statistics."""
        recent_violations = [
            v for v in self.violations
            if v.timestamp > datetime.now() - timedelta(hours=1)
        ]
        
        return {
            'statistics': self.stats.copy(),
            'recent_violations_count': len(recent_violations),
            'violation_rate_per_hour': len(recent_violations),
            'active_scopes': len(self.scope_enforcer.scopes),
            'noise_level': self.noise_controller.current_noise_level.value,
            'auto_mitigation_enabled': self.auto_mitigation_enabled,
            'recent_violations': [v.to_dict() for v in recent_violations[-10:]]  # Last 10
        }


# Global OPSEC manager instance
opsec_manager = OPSECManager()
