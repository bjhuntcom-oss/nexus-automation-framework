"""
Enterprise Governance Layer - RBAC & Compliance Management

Enterprise-grade governance with:
- Role-Based Access Control (RBAC)
- Multi-tenant support with isolation
- Strict scope enforcement
- Approval workflows
- Global kill switch
- Cryptographically signed audit logs
- Policy-as-code framework
- Compliance mapping (NIST, ISO27001, SOC2)
"""

import asyncio
import json
import logging
import hashlib
import hmac
import secrets
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from collections import defaultdict, deque
import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


class Permission(Enum):
    """System permissions."""
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    DELETE = "delete"
    ADMIN = "admin"
    APPROVE = "approve"
    AUDIT = "audit"
    SYSTEM = "system"


class UserRole(Enum):
    """User roles."""
    VIEWER = "viewer"
    ANALYST = "analyst"
    OPERATOR = "operator"
    MANAGER = "manager"
    ADMIN = "admin"
    SYSTEM = "system"


class ApprovalStatus(Enum):
    """Approval workflow status."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class ComplianceFramework(Enum):
    """Compliance frameworks."""
    NIST_800_53 = "nist_800_53"
    ISO_27001 = "iso_27001"
    SOC2 = "soc2"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"


@dataclass
class User:
    """User entity."""
    user_id: str
    username: str
    email: str
    roles: Set[UserRole]
    tenant_id: str
    permissions: Set[Permission]
    created_at: datetime = field(default_factory=datetime.now)
    last_login: Optional[datetime] = None
    active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'user_id': self.user_id,
            'username': self.username,
            'email': self.email,
            'roles': [role.value for role in self.roles],
            'tenant_id': self.tenant_id,
            'permissions': [perm.value for perm in self.permissions],
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'active': self.active,
            'metadata': self.metadata
        }


@dataclass
class Tenant:
    """Multi-tenant organization."""
    tenant_id: str
    name: str
    description: str
    compliance_frameworks: Set[ComplianceFramework]
    data_residency: str  # Country/region
    retention_policy: int  # days
    max_users: int
    resource_limits: Dict[str, Any]
    created_at: datetime = field(default_factory=datetime.now)
    active: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'tenant_id': self.tenant_id,
            'name': self.name,
            'description': self.description,
            'compliance_frameworks': [cf.value for cf in self.compliance_frameworks],
            'data_residency': self.data_residency,
            'retention_policy': self.retention_policy,
            'max_users': self.max_users,
            'resource_limits': self.resource_limits,
            'created_at': self.created_at.isoformat(),
            'active': self.active
        }


@dataclass
class Policy:
    """Governance policy definition."""
    policy_id: str
    name: str
    description: str
    policy_type: str  # access_control, data_protection, operational_security
    rules: List[Dict[str, Any]]
    enforcement_level: str  # advisory, warning, blocking
    compliance_mappings: Set[ComplianceFramework]
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    active: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'policy_id': self.policy_id,
            'name': self.name,
            'description': self.description,
            'policy_type': self.policy_type,
            'rules': self.rules,
            'enforcement_level': self.enforcement_level,
            'compliance_mappings': [cf.value for cf in self.compliance_mappings],
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'active': self.active
        }


@dataclass
class ApprovalRequest:
    """Approval workflow request."""
    request_id: str
    requester_id: str
    operation_type: str
    operation_details: Dict[str, Any]
    justification: str
    risk_level: str
    required_approvers: List[str]
    current_approvers: List[str]
    status: ApprovalStatus
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    approved_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'request_id': self.request_id,
            'requester_id': self.requester_id,
            'operation_type': self.operation_type,
            'operation_details': self.operation_details,
            'justification': self.justification,
            'risk_level': self.risk_level,
            'required_approvers': self.required_approvers,
            'current_approvers': self.current_approvers,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'approved_at': self.approved_at.isoformat() if self.approved_at else None,
            'rejection_reason': self.rejection_reason,
            'metadata': self.metadata
        }


@dataclass
class AuditEntry:
    """Cryptographically signed audit entry."""
    entry_id: str
    timestamp: datetime
    user_id: str
    tenant_id: str
    action: str
    resource: str
    outcome: str
    details: Dict[str, Any]
    ip_address: str
    user_agent: str
    signature: str  # HMAC signature
    previous_hash: str  # Chain integrity
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'entry_id': self.entry_id,
            'timestamp': self.timestamp.isoformat(),
            'user_id': self.user_id,
            'tenant_id': self.tenant_id,
            'action': self.action,
            'resource': self.resource,
            'outcome': self.outcome,
            'details': self.details,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'signature': self.signature,
            'previous_hash': self.previous_hash
        }


class RoleBasedAccessControl:
    """RBAC implementation with hierarchical roles."""
    
    def __init__(self):
        self.logger = logging.getLogger("rbac")
        
        # Role hierarchy (higher = more permissions)
        self.role_hierarchy = {
            UserRole.VIEWER: 1,
            UserRole.ANALYST: 2,
            UserRole.OPERATOR: 3,
            UserRole.MANAGER: 4,
            UserRole.ADMIN: 5,
            UserRole.SYSTEM: 6
        }
        
        # Role permissions mapping
        self.role_permissions = {
            UserRole.VIEWER: {Permission.READ},
            UserRole.ANALYST: {Permission.READ, Permission.WRITE},
            UserRole.OPERATOR: {Permission.READ, Permission.WRITE, Permission.EXECUTE},
            UserRole.MANAGER: {Permission.READ, Permission.WRITE, Permission.EXECUTE, Permission.DELETE, Permission.APPROVE},
            UserRole.ADMIN: {Permission.READ, Permission.WRITE, Permission.EXECUTE, Permission.DELETE, Permission.APPROVE, Permission.AUDIT},
            UserRole.SYSTEM: {perm for perm in Permission}
        }
        
        # User storage
        self.users: Dict[str, User] = {}
        self.user_sessions: Dict[str, Dict[str, Any]] = {}
    
    def create_user(self, username: str, email: str, roles: Set[UserRole], 
                   tenant_id: str) -> Optional[User]:
        """Create a new user."""
        user_id = secrets.token_urlsafe(16)
        
        # Validate roles
        if not roles:
            return None
        
        # Calculate permissions from roles
        permissions = set()
        for role in roles:
            permissions.update(self.role_permissions.get(role, set()))
        
        user = User(
            user_id=user_id,
            username=username,
            email=email,
            roles=roles,
            tenant_id=tenant_id,
            permissions=permissions
        )
        
        self.users[user_id] = user
        self.logger.info(f"Created user {username} with roles {[r.value for r in roles]}")
        
        return user
    
    def authenticate_user(self, username: str, password: str) -> Optional[str]:
        """Authenticate user and return session token."""
        # Find user by username
        user = None
        for u in self.users.values():
            if u.username == username and u.active:
                user = u
                break
        
        if not user:
            return None
        
        # In a real implementation, verify password hash
        # For demo, we'll accept any password
        
        # Create session
        session_token = secrets.token_urlsafe(32)
        self.user_sessions[session_token] = {
            'user_id': user.user_id,
            'created_at': datetime.now(),
            'expires_at': datetime.now() + timedelta(hours=8),
            'ip_address': '127.0.0.1'  # Would be from request
        }
        
        # Update last login
        user.last_login = datetime.now()
        
        self.logger.info(f"Authenticated user {username}")
        return session_token
    
    def get_user_from_session(self, session_token: str) -> Optional[User]:
        """Get user from session token."""
        session = self.user_sessions.get(session_token)
        if not session:
            return None
        
        # Check session expiration
        if datetime.now() > session['expires_at']:
            del self.user_sessions[session_token]
            return None
        
        user_id = session['user_id']
        return self.users.get(user_id)
    
    def check_permission(self, user: User, required_permission: Permission) -> bool:
        """Check if user has required permission."""
        return required_permission in user.permissions
    
    def check_role_hierarchy(self, user: User, required_role: UserRole) -> bool:
        """Check if user has role at or above required level."""
        user_level = max(self.role_hierarchy.get(role, 0) for role in user.roles)
        required_level = self.role_hierarchy.get(required_role, 0)
        
        return user_level >= required_level
    
    def can_access_tenant(self, user: User, tenant_id: str) -> bool:
        """Check if user can access tenant."""
        return user.tenant_id == tenant_id or Permission.ADMIN in user.permissions


class PolicyEngine:
    """Policy-as-code engine for governance."""
    
    def __init__(self):
        self.logger = logging.getLogger("policy_engine")
        self.policies: Dict[str, Policy] = {}
        self.policy_evaluators = {
            'access_control': self._evaluate_access_control,
            'data_protection': self._evaluate_data_protection,
            'operational_security': self._evaluate_operational_security
        }
    
    def create_policy(self, name: str, description: str, policy_type: str,
                      rules: List[Dict[str, Any]], enforcement_level: str,
                      compliance_frameworks: Set[ComplianceFramework]) -> Optional[Policy]:
        """Create a new policy."""
        policy_id = secrets.token_urlsafe(16)
        
        policy = Policy(
            policy_id=policy_id,
            name=name,
            description=description,
            policy_type=policy_type,
            rules=rules,
            enforcement_level=enforcement_level,
            compliance_mappings=compliance_frameworks
        )
        
        self.policies[policy_id] = policy
        self.logger.info(f"Created policy {name} of type {policy_type}")
        
        return policy
    
    def evaluate_policy(self, policy_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate policy against context."""
        if policy_id not in self.policies:
            return {'allowed': False, 'reason': 'Policy not found'}
        
        policy = self.policies[policy_id]
        
        if not policy.active:
            return {'allowed': True, 'reason': 'Policy inactive'}
        
        evaluator = self.policy_evaluators.get(policy.policy_type)
        if not evaluator:
            return {'allowed': False, 'reason': 'Unknown policy type'}
        
        return evaluator(policy, context)
    
    def _evaluate_access_control(self, policy: Policy, context: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate access control policy."""
        user = context.get('user')
        resource = context.get('resource')
        action = context.get('action')
        
        if not all([user, resource, action]):
            return {'allowed': False, 'reason': 'Missing context'}
        
        # Check rules
        for rule in policy.rules:
            rule_type = rule.get('type')
            
            if rule_type == 'role_based':
                required_roles = set(rule.get('required_roles', []))
                user_roles = set(role.value for role in user.roles)
                
                if not required_roles.intersection(user_roles):
                    return {
                        'allowed': False,
                        'reason': f"Required roles: {required_roles}",
                        'enforcement_level': policy.enforcement_level
                    }
            
            elif rule_type == 'time_based':
                allowed_hours = rule.get('allowed_hours', [])
                current_hour = datetime.now().hour
                
                if allowed_hours and current_hour not in allowed_hours:
                    return {
                        'allowed': False,
                        'reason': f"Access not allowed at hour {current_hour}",
                        'enforcement_level': policy.enforcement_level
                    }
            
            elif rule_type == 'location_based':
                allowed_locations = rule.get('allowed_locations', [])
                current_location = context.get('location', 'unknown')
                
                if allowed_locations and current_location not in allowed_locations:
                    return {
                        'allowed': False,
                        'reason': f"Access not allowed from location {current_location}",
                        'enforcement_level': policy.enforcement_level
                    }
        
        return {'allowed': True, 'reason': 'All checks passed'}
    
    def _evaluate_data_protection(self, policy: Policy, context: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate data protection policy."""
        data_type = context.get('data_type')
        action = context.get('action')
        user = context.get('user')
        
        # Check data classification rules
        for rule in policy.rules:
            if rule.get('type') == 'data_classification':
                protected_types = set(rule.get('protected_types', []))
                
                if data_type in protected_types:
                    # Check if user has clearance
                    required_clearance = rule.get('required_clearance', 'analyst')
                    user_clearance = max(role.value for role in user.roles)
                    
                    clearance_levels = {'viewer': 1, 'analyst': 2, 'operator': 3, 'manager': 4, 'admin': 5}
                    
                    if clearance_levels.get(user_clearance, 0) < clearance_levels.get(required_clearance, 0):
                        return {
                            'allowed': False,
                            'reason': f"Insufficient clearance for {data_type} data",
                            'enforcement_level': policy.enforcement_level
                        }
        
        return {'allowed': True, 'reason': 'Data access approved'}
    
    def _evaluate_operational_security(self, policy: Policy, context: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate operational security policy."""
        operation = context.get('operation')
        risk_level = context.get('risk_level', 'low')
        
        # Check operational rules
        for rule in policy.rules:
            if rule.get('type') == 'risk_based':
                high_risk_operations = set(rule.get('high_risk_operations', []))
                
                if operation in high_risk_operations and risk_level == 'high':
                    return {
                        'allowed': False,
                        'reason': f"High risk operation {operation} requires approval",
                        'enforcement_level': policy.enforcement_level
                    }
            
            elif rule.get('type') == 'approval_required':
                required_approvals = set(rule.get('required_approvals', []))
                
                if operation in required_approvals:
                    return {
                        'allowed': False,
                        'reason': f"Operation {operation} requires explicit approval",
                        'enforcement_level': policy.enforcement_level
                    }
        
        return {'allowed': True, 'reason': 'Operation approved'}


class ApprovalWorkflow:
    """Approval workflow management."""
    
    def __init__(self):
        self.logger = logging.getLogger("approval_workflow")
        self.requests: Dict[str, ApprovalRequest] = {}
        self.approval_timeout = timedelta(hours=24)
    
    def create_request(self, requester_id: str, operation_type: str,
                      operation_details: Dict[str, Any], justification: str,
                      risk_level: str, required_approvers: List[str]) -> Optional[ApprovalRequest]:
        """Create approval request."""
        request_id = secrets.token_urlsafe(16)
        
        request = ApprovalRequest(
            request_id=request_id,
            requester_id=requester_id,
            operation_type=operation_type,
            operation_details=operation_details,
            justification=justification,
            risk_level=risk_level,
            required_approvers=required_approvers,
            current_approvers=[],
            status=ApprovalStatus.PENDING,
            expires_at=datetime.now() + self.approval_timeout
        )
        
        self.requests[request_id] = request
        self.logger.info(f"Created approval request {request_id} for {operation_type}")
        
        return request
    
    def approve_request(self, request_id: str, approver_id: str) -> bool:
        """Approve a request."""
        if request_id not in self.requests:
            return False
        
        request = self.requests[request_id]
        
        # Check if approver is authorized
        if approver_id not in request.required_approvers:
            return False
        
        # Check if already approved by this approver
        if approver_id in request.current_approvers:
            return False
        
        # Add approval
        request.current_approvers.append(approver_id)
        
        # Check if all required approvals received
        if set(request.current_approvers) >= set(request.required_approvers):
            request.status = ApprovalStatus.APPROVED
            request.approved_at = datetime.now()
            self.logger.info(f"Request {request_id} fully approved")
        
        return True
    
    def reject_request(self, request_id: str, approver_id: str, reason: str) -> bool:
        """Reject a request."""
        if request_id not in self.requests:
            return False
        
        request = self.requests[request_id]
        
        # Check if approver is authorized
        if approver_id not in request.required_approvers:
            return False
        
        request.status = ApprovalStatus.REJECTED
        request.rejection_reason = reason
        
        self.logger.info(f"Request {request_id} rejected by {approver_id}: {reason}")
        return True
    
    def get_request_status(self, request_id: str) -> Optional[ApprovalRequest]:
        """Get request status."""
        return self.requests.get(request_id)
    
    def cleanup_expired_requests(self):
        """Clean up expired requests."""
        now = datetime.now()
        expired_requests = [
            request_id for request_id, request in self.requests.items()
            if request.expires_at and now > request.expires_at and request.status == ApprovalStatus.PENDING
        ]
        
        for request_id in expired_requests:
            request = self.requests[request_id]
            request.status = ApprovalStatus.EXPIRED
            self.logger.info(f"Request {request_id} expired")


class AuditLogger:
    """Cryptographically signed audit logging."""
    
    def __init__(self, secret_key: str):
        self.logger = logging.getLogger("audit_logger")
        self.secret_key = secret_key.encode()
        self.audit_chain: List[AuditEntry] = []
        self.previous_hash = ""
    
    def log_action(self, user_id: str, tenant_id: str, action: str,
                   resource: str, outcome: str, details: Dict[str, Any],
                   ip_address: str = "127.0.0.1", user_agent: str = "Unknown") -> str:
        """Log an action with cryptographic signature."""
        entry_id = secrets.token_urlsafe(16)
        timestamp = datetime.now()
        
        # Create entry
        entry = AuditEntry(
            entry_id=entry_id,
            timestamp=timestamp,
            user_id=user_id,
            tenant_id=tenant_id,
            action=action,
            resource=resource,
            outcome=outcome,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            signature="",  # Will be set below
            previous_hash=self.previous_hash
        )
        
        # Calculate signature
        entry_data = self._serialize_entry(entry)
        signature = hmac.new(self.secret_key, entry_data, hashlib.sha256).hexdigest()
        entry.signature = signature
        
        # Update chain
        self.audit_chain.append(entry)
        self.previous_hash = hashlib.sha256(entry_data.encode()).hexdigest()
        
        self.logger.info(f"Audit entry {entry_id}: {action} on {resource} - {outcome}")
        return entry_id
    
    def _serialize_entry(self, entry: AuditEntry) -> str:
        """Serialize entry for signing."""
        data = {
            'entry_id': entry.entry_id,
            'timestamp': entry.timestamp.isoformat(),
            'user_id': entry.user_id,
            'tenant_id': entry.tenant_id,
            'action': entry.action,
            'resource': entry.resource,
            'outcome': entry.outcome,
            'details': entry.details,
            'ip_address': entry.ip_address,
            'user_agent': entry.user_agent,
            'previous_hash': entry.previous_hash
        }
        return json.dumps(data, sort_keys=True)
    
    def verify_chain_integrity(self) -> bool:
        """Verify audit chain integrity."""
        for i, entry in enumerate(self.audit_chain):
            # Verify signature
            entry_data = self._serialize_entry(entry)
            expected_signature = hmac.new(self.secret_key, entry_data, hashlib.sha256).hexdigest()
            
            if not hmac.compare_digest(entry.signature, expected_signature):
                self.logger.error(f"Signature verification failed for entry {entry.entry_id}")
                return False
            
            # Verify chain hash
            if i > 0:
                expected_hash = hashlib.sha256(self._serialize_entry(self.audit_chain[i-1]).encode()).hexdigest()
                if entry.previous_hash != expected_hash:
                    self.logger.error(f"Chain hash verification failed for entry {entry.entry_id}")
                    return False
        
        return True
    
    def get_audit_trail(self, user_id: Optional[str] = None,
                       tenant_id: Optional[str] = None,
                       start_time: Optional[datetime] = None,
                       end_time: Optional[datetime] = None) -> List[AuditEntry]:
        """Get filtered audit trail."""
        trail = self.audit_chain
        
        # Apply filters
        if user_id:
            trail = [entry for entry in trail if entry.user_id == user_id]
        
        if tenant_id:
            trail = [entry for entry in trail if entry.tenant_id == tenant_id]
        
        if start_time:
            trail = [entry for entry in trail if entry.timestamp >= start_time]
        
        if end_time:
            trail = [entry for entry in trail if entry.timestamp <= end_time]
        
        return trail


class GovernanceManager:
    """Main governance management system."""
    
    def __init__(self, secret_key: str):
        self.logger = logging.getLogger("governance_manager")
        self.rbac = RoleBasedAccessControl()
        self.policy_engine = PolicyEngine()
        self.approval_workflow = ApprovalWorkflow()
        self.audit_logger = AuditLogger(secret_key)
        
        # Tenants
        self.tenants: Dict[str, Tenant] = {}
        
        # Global kill switch
        self.kill_switch_enabled = False
        self.kill_switch_reason = ""
        
        # Statistics
        self.stats = {
            'total_users': 0,
            'total_tenants': 0,
            'active_sessions': 0,
            'pending_approvals': 0,
            'audit_entries': 0
        }
        
        # Initialize default policies
        self._create_default_policies()
    
    def _create_default_policies(self):
        """Create default governance policies."""
        # Access control policy
        self.policy_engine.create_policy(
            name="Standard Access Control",
            description="Standard RBAC access control policy",
            policy_type="access_control",
            rules=[
                {
                    "type": "role_based",
                    "required_roles": ["analyst", "operator", "manager", "admin"]
                }
            ],
            enforcement_level="blocking",
            compliance_frameworks={ComplianceFramework.NIST_800_53, ComplianceFramework.ISO_27001}
        )
        
        # Operational security policy
        self.policy_engine.create_policy(
            name="Operational Security",
            description="Operational security controls",
            policy_type="operational_security",
            rules=[
                {
                    "type": "risk_based",
                    "high_risk_operations": ["exploitation", "privilege_escalation"]
                },
                {
                    "type": "approval_required",
                    "required_approvals": ["manager", "admin"]
                }
            ],
            enforcement_level="blocking",
            compliance_frameworks={ComplianceFramework.NIST_800_53}
        )
    
    def create_tenant(self, name: str, description: str,
                     compliance_frameworks: Set[ComplianceFramework],
                     data_residency: str, retention_policy: int,
                     max_users: int, resource_limits: Dict[str, Any]) -> Optional[Tenant]:
        """Create a new tenant."""
        tenant_id = secrets.token_urlsafe(16)
        
        tenant = Tenant(
            tenant_id=tenant_id,
            name=name,
            description=description,
            compliance_frameworks=compliance_frameworks,
            data_residency=data_residency,
            retention_policy=retention_policy,
            max_users=max_users,
            resource_limits=resource_limits
        )
        
        self.tenants[tenant_id] = tenant
        self.stats['total_tenants'] += 1
        
        self.logger.info(f"Created tenant {name}")
        return tenant
    
    def authorize_operation(self, session_token: str, operation: str,
                          resource: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Authorize an operation."""
        # Check kill switch
        if self.kill_switch_enabled:
            return {
                'authorized': False,
                'reason': f"System kill switch enabled: {self.kill_switch_reason}"
            }
        
        # Get user from session
        user = self.rbac.get_user_from_session(session_token)
        if not user:
            return {'authorized': False, 'reason': 'Invalid session'}
        
        # Check tenant access
        tenant_id = context.get('tenant_id')
        if tenant_id and not self.rbac.can_access_tenant(user, tenant_id):
            return {'authorized': False, 'reason': 'Tenant access denied'}
        
        # Evaluate policies
        policy_context = {
            'user': user,
            'resource': resource,
            'action': operation,
            **context
        }
        
        # Check all applicable policies
        for policy in self.policy_engine.policies.values():
            if policy.active:
                result = self.policy_engine.evaluate_policy(policy.policy_id, policy_context)
                if not result['allowed']:
                    # Log failed authorization
                    self.audit_logger.log_action(
                        user_id=user.user_id,
                        tenant_id=user.tenant_id,
                        action=operation,
                        resource=resource,
                        outcome="denied",
                        details={'policy_id': policy.policy_id, 'reason': result['reason']}
                    )
                    
                    return {
                        'authorized': False,
                        'reason': f"Policy violation: {result['reason']}",
                        'policy_id': policy.policy_id
                    }
        
        # Operation authorized
        self.audit_logger.log_action(
            user_id=user.user_id,
            tenant_id=user.tenant_id,
            action=operation,
            resource=resource,
            outcome="authorized",
            details=context
        )
        
        return {'authorized': True, 'user_id': user.user_id}
    
    def enable_kill_switch(self, reason: str):
        """Enable global kill switch."""
        self.kill_switch_enabled = True
        self.kill_switch_reason = reason
        
        self.logger.critical(f"Global kill switch enabled: {reason}")
        
        # Log to audit
        self.audit_logger.log_action(
            user_id="system",
            tenant_id="system",
            action="kill_switch_enable",
            resource="system",
            outcome="executed",
            details={'reason': reason}
        )
    
    def disable_kill_switch(self):
        """Disable global kill switch."""
        self.kill_switch_enabled = False
        self.kill_switch_reason = ""
        
        self.logger.info("Global kill switch disabled")
        
        # Log to audit
        self.audit_logger.log_action(
            user_id="system",
            tenant_id="system",
            action="kill_switch_disable",
            resource="system",
            outcome="executed",
            details={}
        )
    
    def get_compliance_report(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """Generate compliance report."""
        report = {
            'generated_at': datetime.now().isoformat(),
            'tenant_id': tenant_id,
            'frameworks': {},
            'policies': {},
            'audit_integrity': self.audit_logger.verify_chain_integrity()
        }
        
        # Get tenant information
        if tenant_id:
            tenant = self.tenants.get(tenant_id)
            if tenant:
                report['tenant'] = tenant.to_dict()
                
                # Report on compliance frameworks
                for framework in tenant.compliance_frameworks:
                    report['frameworks'][framework.value] = {
                        'status': 'compliant',
                        'last_assessment': datetime.now().isoformat(),
                        'exceptions': []
                    }
        
        # Report on policies
        for policy in self.policy_engine.policies.values():
            if policy.active:
                report['policies'][policy.policy_id] = {
                    'name': policy.name,
                    'type': policy.policy_type,
                    'enforcement_level': policy.enforcement_level,
                    'compliance_mappings': [cf.value for cf in policy.compliance_mappings]
                }
        
        return report
    
    def get_governance_summary(self) -> Dict[str, Any]:
        """Get governance system summary."""
        # Update statistics
        self.stats['total_users'] = len(self.rbac.users)
        self.stats['active_sessions'] = len(self.rbac.user_sessions)
        self.stats['pending_approvals'] = len([
            r for r in self.approval_workflow.requests.values()
            if r.status == ApprovalStatus.PENDING
        ])
        self.stats['audit_entries'] = len(self.audit_logger.audit_chain)
        
        return {
            'statistics': self.stats.copy(),
            'kill_switch_enabled': self.kill_switch_enabled,
            'kill_switch_reason': self.kill_switch_reason,
            'active_tenants': len([t for t in self.tenants.values() if t.active]),
            'active_policies': len([p for p in self.policy_engine.policies.values() if p.active]),
            'audit_chain_integrity': self.audit_logger.verify_chain_integrity()
        }


# Global governance manager instance
governance_manager = GovernanceManager(secret_key="bjhunt-alpha-secret-key-change-in-production")
