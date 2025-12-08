# agnoguard/guardrails/tool_access_control.py
"""
Production-grade tool access control guardrails for LLM-powered agents.

Implements capability-based, zero-trust access control with:
- Strong identity & attestation
- Least-privilege capabilities
- Context-aware runtime policy enforcement
- Immutable audit trails
- Human-in-the-loop approval gates
- Active monitoring & anomaly detection

Based on NIST AI RMF, Zero-Trust API patterns, and industry best practices.
"""

import re
import hashlib
import json
import time
from typing import Dict, Any, Optional, List, Set, Tuple, Callable
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging

# Assuming base classes are imported from core
from ..core.base import ToolGuardrail, GuardrailResult, GuardrailAction, GuardrailSeverity

logger = logging.getLogger(__name__)


# ============================================================================
# 1. POLICY & TAXONOMY
# ============================================================================

class ToolSensitivity(Enum):
    """Tool classification by sensitivity level"""
    PUBLIC_READ = "public_read"              # Public data, read-only
    INTERNAL_READ = "internal_read"          # Internal data, read-only
    INTERNAL_WRITE = "internal_write"        # Internal data modifications
    SENSITIVE_WRITE = "sensitive_write"      # Financial, PII modifications
    PRIVILEGED_ADMIN = "privileged_admin"    # System admin operations
    EXTERNAL_CREDENTIAL = "external_credential"  # Uses external credentials/secrets


class ToolAction(Enum):
    """Granular actions on tools"""
    INVOKE = "invoke"
    READ = "read"
    WRITE = "write"
    ESCALATE = "escalate"
    LIST = "list"
    DELETE = "delete"


class PrincipalType(Enum):
    """Type of principal making the request"""
    HUMAN = "human"
    AGENT = "agent"
    SERVICE = "service"
    GUEST = "guest"


class IdentityStrength(Enum):
    """Identity verification strength"""
    UNVERIFIED = 0
    EMAIL_VERIFIED = 1
    MFA_VERIFIED = 2
    DEVICE_ATTESTED = 3
    KYC_VERIFIED = 4


class AgentRole(Enum):
    """Agent role classification"""
    TASK_ONLY = "task_only"        # Single-task agents
    ASSISTANT = "assistant"         # General assistants
    ORCHESTRATOR = "orchestrator"   # Multi-agent orchestrators
    ADMIN = "admin"                 # Administrative agents


class PolicyDecision(Enum):
    """Policy decision outcomes"""
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    ALLOW_WITH_SANITIZATION = "allow_with_sanitization"
    AUDIT_ONLY = "audit_only"
    QUARANTINE = "quarantine"


# ============================================================================
# 2. IDENTITY & CAPABILITY MODELS
# ============================================================================

@dataclass
class AgentIdentity:
    """Strong identity for agents"""
    agent_id: str
    agent_type: PrincipalType
    agent_role: AgentRole
    owner_team: str
    purpose: str
    creation_time: datetime
    identity_strength: IdentityStrength
    attestation_signature: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_attested(self) -> bool:
        """Check if agent has valid attestation"""
        return self.attestation_signature is not None
    
    def get_trust_score(self) -> float:
        """Calculate trust score (0.0 to 1.0) based on identity attributes"""
        score = 0.0
        
        # Base score from identity strength
        strength_scores = {
            IdentityStrength.UNVERIFIED: 0.1,
            IdentityStrength.EMAIL_VERIFIED: 0.3,
            IdentityStrength.MFA_VERIFIED: 0.5,
            IdentityStrength.DEVICE_ATTESTED: 0.7,
            IdentityStrength.KYC_VERIFIED: 0.9
        }
        score += strength_scores.get(self.identity_strength, 0.1)
        
        # Bonus for attestation
        if self.is_attested():
            score += 0.1
        
        return min(1.0, score)


@dataclass
class CapabilityToken:
    """Capability token granting specific permissions"""
    token_id: str
    agent_id: str
    tool_name: str
    allowed_actions: List[ToolAction]
    constraints: Dict[str, Any]  # e.g., {"max_amount": 1000, "rate_limit": "10/min"}
    issued_at: datetime
    expires_at: datetime
    session_id: Optional[str] = None
    nonce: Optional[str] = None
    signature: Optional[str] = None
    
    def is_valid(self) -> bool:
        """Check if token is still valid"""
        now = datetime.utcnow()
        return self.issued_at <= now < self.expires_at
    
    def is_expired(self) -> bool:
        """Check if token is expired"""
        return datetime.utcnow() >= self.expires_at
    
    def verify_signature(self, signing_key: str) -> bool:
        """Verify token signature (simplified - use proper crypto in production)"""
        if not self.signature:
            return False
        
        # In production: use proper JWT/JWS verification
        payload = f"{self.token_id}:{self.agent_id}:{self.tool_name}:{self.issued_at.isoformat()}"
        expected = hashlib.sha256(f"{payload}:{signing_key}".encode()).hexdigest()
        return self.signature == expected
    
    def allows_action(self, action: ToolAction) -> bool:
        """Check if token allows specific action"""
        return action in self.allowed_actions
    
    def check_constraints(self, tool_args: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Verify tool arguments against capability constraints.
        Returns (passed, error_message)
        """
        for constraint_name, constraint_value in self.constraints.items():
            
            # Amount constraint
            if constraint_name == "max_amount" and "amount" in tool_args:
                if tool_args["amount"] > constraint_value:
                    return False, f"Amount {tool_args['amount']} exceeds maximum {constraint_value}"
            
            # Destination pattern constraint
            if constraint_name == "dest_account_pattern" and "dest_account" in tool_args:
                pattern = constraint_value
                if not re.match(pattern, tool_args["dest_account"]):
                    return False, f"Destination account does not match allowed pattern {pattern}"
            
            # Row limit constraint
            if constraint_name == "max_rows" and "limit" in tool_args:
                if tool_args["limit"] > constraint_value:
                    return False, f"Row limit {tool_args['limit']} exceeds maximum {constraint_value}"
            
            # Rate limit (tracked separately in runtime)
            if constraint_name == "rate_limit":
                pass  # Handled by rate limiter
            
            # Generic field constraints
            if constraint_name.startswith("allowed_") and constraint_name.replace("allowed_", "") in tool_args:
                field = constraint_name.replace("allowed_", "")
                if tool_args[field] not in constraint_value:
                    return False, f"Field '{field}' value not in allowed set"
        
        return True, None


@dataclass
class RuntimeContext:
    """Runtime context for policy decisions"""
    session_id: str
    conversation_intent: Optional[str] = None
    user_identity: Optional[str] = None
    user_verified: bool = False
    geo_location: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    recent_tool_calls: List[str] = field(default_factory=list)
    rate_limit_state: Dict[str, int] = field(default_factory=dict)
    risk_score: float = 0.0
    environment: str = "production"
    ip_address: Optional[str] = None
    device_fingerprint: Optional[str] = None
    
    def add_tool_call(self, tool_name: str):
        """Track tool call for rate limiting and anomaly detection"""
        self.recent_tool_calls.append(tool_name)
        # Keep only last 100 calls
        if len(self.recent_tool_calls) > 100:
            self.recent_tool_calls = self.recent_tool_calls[-100:]


# ============================================================================
# 3. TOOL ACCESS POLICY (TAP)
# ============================================================================

@dataclass
class ToolPolicy:
    """Policy for a specific tool"""
    tool_name: str
    sensitivity: ToolSensitivity
    allowed_roles: Set[AgentRole]
    required_identity_strength: IdentityStrength
    requires_approval: bool = False
    approval_type: str = "single"  # "single", "multi", "stepwise"
    max_invocations_per_hour: Optional[int] = None
    allowed_environments: Set[str] = field(default_factory=lambda: {"production", "staging", "development"})
    allowed_geo_regions: Optional[Set[str]] = None
    input_sanitization_required: bool = False
    output_redaction_required: bool = False
    audit_required: bool = True
    custom_validators: List[Callable] = field(default_factory=list)


class ToolAccessPolicy:
    """
    Centralized Tool Access Policy (TAP) - single source of truth.
    Maps (identity + context) -> decision
    """
    
    def __init__(self):
        self.policies: Dict[str, ToolPolicy] = {}
        self.global_rules: List[Callable] = []
        self.version = "1.0.0"
        self.last_updated = datetime.utcnow()
    
    def register_tool(self, policy: ToolPolicy):
        """Register a tool with its policy"""
        self.policies[policy.tool_name] = policy
        logger.info(f"Registered tool policy: {policy.tool_name} (sensitivity: {policy.sensitivity.value})")
    
    def get_policy(self, tool_name: str) -> Optional[ToolPolicy]:
        """Retrieve policy for a tool"""
        return self.policies.get(tool_name)
    
    def add_global_rule(self, rule: Callable):
        """Add a global rule that applies to all tools"""
        self.global_rules.append(rule)
    
    def evaluate(
        self,
        tool_name: str,
        agent_identity: AgentIdentity,
        capability_token: Optional[CapabilityToken],
        runtime_context: RuntimeContext,
        tool_args: Dict[str, Any]
    ) -> Tuple[PolicyDecision, str, Dict[str, Any]]:
        """
        Evaluate policy for a tool call.
        Returns (decision, reason, metadata)
        """
        
        # Check if tool is registered
        policy = self.get_policy(tool_name)
        if not policy:
            return (
                PolicyDecision.DENY,
                f"Tool '{tool_name}' not registered in policy",
                {"tool_name": tool_name}
            )
        
        metadata = {
            "tool_name": tool_name,
            "sensitivity": policy.sensitivity.value,
            "agent_id": agent_identity.agent_id,
            "evaluation_time": datetime.utcnow().isoformat()
        }
        
        # 1. Check agent role
        if agent_identity.agent_role not in policy.allowed_roles:
            return (
                PolicyDecision.DENY,
                f"Agent role '{agent_identity.agent_role.value}' not authorized for this tool",
                metadata
            )
        
        # 2. Check identity strength
        if agent_identity.identity_strength.value < policy.required_identity_strength.value:
            return (
                PolicyDecision.DENY,
                f"Insufficient identity strength (requires {policy.required_identity_strength.value})",
                metadata
            )
        
        # 3. Check capability token
        if not capability_token:
            return (
                PolicyDecision.DENY,
                "No capability token provided",
                metadata
            )
        
        if not capability_token.is_valid():
            return (
                PolicyDecision.DENY,
                "Capability token is invalid or expired",
                metadata
            )
        
        if capability_token.tool_name != tool_name:
            return (
                PolicyDecision.DENY,
                "Capability token does not match requested tool",
                metadata
            )
        
        # 4. Check capability constraints
        constraint_passed, constraint_error = capability_token.check_constraints(tool_args)
        if not constraint_passed:
            return (
                PolicyDecision.DENY,
                f"Capability constraint violated: {constraint_error}",
                metadata
            )
        
        # 5. Check environment
        if runtime_context.environment not in policy.allowed_environments:
            return (
                PolicyDecision.DENY,
                f"Tool not allowed in environment '{runtime_context.environment}'",
                metadata
            )
        
        # 6. Check geo restrictions
        if policy.allowed_geo_regions and runtime_context.geo_location:
            if runtime_context.geo_location not in policy.allowed_geo_regions:
                return (
                    PolicyDecision.DENY,
                    f"Tool not allowed in geo region '{runtime_context.geo_location}'",
                    metadata
                )
        
        # 7. Check rate limits
        if policy.max_invocations_per_hour:
            rate_key = f"{tool_name}:{agent_identity.agent_id}"
            current_count = runtime_context.rate_limit_state.get(rate_key, 0)
            if current_count >= policy.max_invocations_per_hour:
                return (
                    PolicyDecision.DENY,
                    f"Rate limit exceeded ({policy.max_invocations_per_hour}/hour)",
                    metadata
                )
        
        # 8. Check risk score
        if runtime_context.risk_score > 0.8:
            return (
                PolicyDecision.QUARANTINE,
                f"High risk score detected ({runtime_context.risk_score:.2f})",
                metadata
            )
        
        # 9. Apply custom validators
        for validator in policy.custom_validators:
            passed, reason = validator(tool_args, runtime_context)
            if not passed:
                return (
                    PolicyDecision.DENY,
                    f"Custom validation failed: {reason}",
                    metadata
                )
        
        # 10. Apply global rules
        for rule in self.global_rules:
            decision, reason = rule(tool_name, agent_identity, runtime_context, tool_args)
            if decision != PolicyDecision.ALLOW:
                return (decision, reason, metadata)
        
        # 11. Check if approval required
        if policy.requires_approval:
            return (
                PolicyDecision.REQUIRE_APPROVAL,
                f"Tool requires {policy.approval_type} approval",
                {**metadata, "approval_type": policy.approval_type}
            )
        
        # 12. Check if sanitization required
        if policy.input_sanitization_required or policy.output_redaction_required:
            return (
                PolicyDecision.ALLOW_WITH_SANITIZATION,
                "Tool call allowed with sanitization",
                {
                    **metadata,
                    "input_sanitization": policy.input_sanitization_required,
                    "output_redaction": policy.output_redaction_required
                }
            )
        
        # All checks passed
        return (
            PolicyDecision.ALLOW,
            "All policy checks passed",
            metadata
        )


# ============================================================================
# 4. APPROVAL SYSTEM
# ============================================================================

@dataclass
class ApprovalRequest:
    """Request for human approval"""
    request_id: str
    tool_name: str
    agent_id: str
    tool_args: Dict[str, Any]  # Redacted as needed
    reason: str
    risk_score: float
    approval_type: str
    requested_at: datetime
    status: str = "pending"  # "pending", "approved", "denied"
    approver_id: Optional[str] = None
    approved_at: Optional[datetime] = None
    comments: Optional[str] = None


class ApprovalSystem:
    """Human-in-the-loop approval system"""
    
    def __init__(self):
        self.pending_approvals: Dict[str, ApprovalRequest] = {}
        self.approval_history: List[ApprovalRequest] = []
    
    def request_approval(
        self,
        tool_name: str,
        agent_id: str,
        tool_args: Dict[str, Any],
        reason: str,
        risk_score: float,
        approval_type: str
    ) -> str:
        """Create an approval request and return request ID"""
        request_id = hashlib.sha256(
            f"{tool_name}:{agent_id}:{time.time()}".encode()
        ).hexdigest()[:16]
        
        # Redact sensitive fields in tool_args
        redacted_args = self._redact_sensitive_args(tool_args)
        
        request = ApprovalRequest(
            request_id=request_id,
            tool_name=tool_name,
            agent_id=agent_id,
            tool_args=redacted_args,
            reason=reason,
            risk_score=risk_score,
            approval_type=approval_type,
            requested_at=datetime.utcnow()
        )
        
        self.pending_approvals[request_id] = request
        logger.info(f"Approval request created: {request_id} for tool {tool_name}")
        
        return request_id
    
    def approve(self, request_id: str, approver_id: str, comments: Optional[str] = None) -> bool:
        """Approve a request"""
        if request_id not in self.pending_approvals:
            logger.warning(f"Approval request not found: {request_id}")
            return False
        
        request = self.pending_approvals[request_id]
        request.status = "approved"
        request.approver_id = approver_id
        request.approved_at = datetime.utcnow()
        request.comments = comments
        
        self.approval_history.append(request)
        del self.pending_approvals[request_id]
        
        logger.info(f"Approval request approved: {request_id} by {approver_id}")
        return True
    
    def deny(self, request_id: str, approver_id: str, comments: Optional[str] = None) -> bool:
        """Deny a request"""
        if request_id not in self.pending_approvals:
            logger.warning(f"Approval request not found: {request_id}")
            return False
        
        request = self.pending_approvals[request_id]
        request.status = "denied"
        request.approver_id = approver_id
        request.approved_at = datetime.utcnow()
        request.comments = comments
        
        self.approval_history.append(request)
        del self.pending_approvals[request_id]
        
        logger.info(f"Approval request denied: {request_id} by {approver_id}")
        return True
    
    def get_status(self, request_id: str) -> Optional[str]:
        """Get status of an approval request"""
        if request_id in self.pending_approvals:
            return "pending"
        
        for req in self.approval_history:
            if req.request_id == request_id:
                return req.status
        
        return None
    
    def _redact_sensitive_args(self, tool_args: Dict[str, Any]) -> Dict[str, Any]:
        """Redact sensitive fields from tool arguments"""
        sensitive_fields = {"password", "secret", "api_key", "token", "credential"}
        
        redacted = {}
        for key, value in tool_args.items():
            if any(sensitive in key.lower() for sensitive in sensitive_fields):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = value
        
        return redacted


# ============================================================================
# 5. AUDIT LOGGER
# ============================================================================

@dataclass
class AuditEntry:
    """Immutable audit log entry"""
    entry_id: str
    timestamp: datetime
    agent_id: str
    tool_name: str
    action: str
    decision: PolicyDecision
    reason: str
    tool_args_hash: str  # Hash of arguments for privacy
    capability_token_id: Optional[str]
    context_snapshot: Dict[str, Any]
    metadata: Dict[str, Any]


class AuditLogger:
    """Immutable audit trail for all tool access decisions"""
    
    def __init__(self):
        self.entries: List[AuditEntry] = []
    
    def log(
        self,
        agent_id: str,
        tool_name: str,
        action: str,
        decision: PolicyDecision,
        reason: str,
        tool_args: Dict[str, Any],
        capability_token: Optional[CapabilityToken],
        context: RuntimeContext,
        metadata: Dict[str, Any]
    ):
        """Log an audit entry"""
        entry_id = hashlib.sha256(
            f"{agent_id}:{tool_name}:{time.time()}".encode()
        ).hexdigest()
        
        # Hash tool arguments (don't store plaintext)
        args_hash = hashlib.sha256(
            json.dumps(tool_args, sort_keys=True).encode()
        ).hexdigest()
        
        # Create context snapshot (minimal PII)
        context_snapshot = {
            "session_id": context.session_id,
            "environment": context.environment,
            "risk_score": context.risk_score,
            "timestamp": context.timestamp.isoformat()
        }
        
        entry = AuditEntry(
            entry_id=entry_id,
            timestamp=datetime.utcnow(),
            agent_id=agent_id,
            tool_name=tool_name,
            action=action,
            decision=decision,
            reason=reason,
            tool_args_hash=args_hash,
            capability_token_id=capability_token.token_id if capability_token else None,
            context_snapshot=context_snapshot,
            metadata=metadata
        )
        
        self.entries.append(entry)
        logger.info(f"Audit entry created: {entry_id} - {decision.value}")
    
    def get_entries_for_agent(self, agent_id: str, limit: int = 100) -> List[AuditEntry]:
        """Retrieve audit entries for a specific agent"""
        return [e for e in self.entries if e.agent_id == agent_id][-limit:]
    
    def get_denied_attempts(self, hours: int = 24) -> List[AuditEntry]:
        """Get all denied attempts in the last N hours"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        return [
            e for e in self.entries
            if e.decision == PolicyDecision.DENY and e.timestamp >= cutoff
        ]


# ============================================================================
# 6. MAIN GUARDRAIL IMPLEMENTATION
# ============================================================================

class ToolAccessControlGuardrail(ToolGuardrail):
    """
    Production-grade tool access control guardrail.
    
    Implements:
    - Capability-based access control
    - Zero-trust policy enforcement
    - Context-aware decisions
    - Human approval workflows
    - Immutable audit trails
    - Anomaly detection
    
    Args:
        policy: ToolAccessPolicy instance
        approval_system: ApprovalSystem instance
        audit_logger: AuditLogger instance
        signing_key: Key for capability token verification
        enable_anomaly_detection: Enable behavioral anomaly detection
        anomaly_threshold: Risk score threshold for quarantine
        enable_rate_limiting: Enable per-tool rate limiting
    """
    
    def __init__(
        self,
        policy: ToolAccessPolicy,
        approval_system: Optional[ApprovalSystem] = None,
        audit_logger: Optional[AuditLogger] = None,
        signing_key: str = "default_signing_key_change_in_production",
        enable_anomaly_detection: bool = True,
        anomaly_threshold: float = 0.8,
        enable_rate_limiting: bool = True,
        **kwargs
    ):
        super().__init__(**kwargs)
        
        self.policy = policy
        self.approval_system = approval_system or ApprovalSystem()
        self.audit_logger = audit_logger or AuditLogger()
        self.signing_key = signing_key
        self.enable_anomaly_detection = enable_anomaly_detection
        self.anomaly_threshold = anomaly_threshold
        self.enable_rate_limiting = enable_rate_limiting
        
        # Runtime state
        self.active_sessions: Dict[str, RuntimeContext] = {}
        self.rate_limit_counters: Dict[str, List[datetime]] = {}
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        """
        Not used for tool guardrails - use check_tool_call instead.
        """
        return GuardrailResult(
            passed=False,
            action=GuardrailAction.BLOCK,
            severity=GuardrailSeverity.ERROR,
            message="Use check_tool_call for tool access control",
            metadata={}
        )
    
    def check_tool_call(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> GuardrailResult:
        """
        Check if a tool call is allowed.
        
        Args:
            tool_name: Name of the tool to call
            tool_args: Arguments for the tool
            context: Runtime context including:
                - agent_identity: AgentIdentity object
                - capability_token: CapabilityToken object
                - runtime_context: RuntimeContext object
                
        Returns:
            GuardrailResult with decision and metadata
        """
        
        # Extract required context
        if not context:
            return self._create_result(
                PolicyDecision.DENY,
                "No context provided",
                tool_name,
                {}
            )
        
        agent_identity = context.get("agent_identity")
        capability_token = context.get("capability_token")
        runtime_context = context.get("runtime_context")
        
        if not agent_identity or not isinstance(agent_identity, AgentIdentity):
            return self._create_result(
                PolicyDecision.DENY,
                "Invalid or missing agent identity",
                tool_name,
                {}
            )
        
        if not runtime_context or not isinstance(runtime_context, RuntimeContext):
            return self._create_result(
                PolicyDecision.DENY,
                "Invalid or missing runtime context",
                tool_name,
                {}
            )
        
        # 1. Verify capability token signature
        if capability_token:
            if not capability_token.verify_signature(self.signing_key):
                self.audit_logger.log(
                    agent_identity.agent_id,
                    tool_name,
                    "check_tool_call",
                    PolicyDecision.DENY,
                    "Invalid capability token signature",
                    tool_args,
                    capability_token,
                    runtime_context,
                    {"signature_invalid": True}
                )
                return self._create_result(
                    PolicyDecision.DENY,
                    "Invalid capability token signature",
                    tool_name,
                    {"signature_invalid": True}
                )
        
        # 2. Anomaly detection (if enabled)
        if self.enable_anomaly_detection:
            risk_score = self._calculate_risk_score(
                agent_identity,
                tool_name,
                tool_args,
                runtime_context
            )
            runtime_context.risk_score = risk_score
            
            if risk_score >= self.anomaly_threshold:
                self.audit_logger.log(
                    agent_identity.agent_id,
                    tool_name,
                    "check_tool_call",
                    PolicyDecision.QUARANTINE,
                    f"High risk score: {risk_score:.2f}",
                    tool_args,
                    capability_token,
                    runtime_context,
                    {"risk_score": risk_score}
                )
                return self._create_result(
                    PolicyDecision.QUARANTINE,
                    f"Anomalous behavior detected (risk: {risk_score:.2f})",
                    tool_name,
                    {"risk_score": risk_score}
                )
        
        # 3. Rate limiting (if enabled)
        if self.enable_rate_limiting:
            if not self._check_rate_limit(agent_identity.agent_id, tool_name):
                self.audit_logger.log(
                    agent_identity.agent_id,
                    tool_name,
                    "check_tool_call",
                    PolicyDecision.DENY,
                    "Rate limit exceeded",
                    tool_args,
                    capability_token,
                    runtime_context,
                    {"rate_limited": True}
                )
                return self._create_result(
                    PolicyDecision.DENY,
                    "Rate limit exceeded for this tool",
                    tool_name,
                    {"rate_limited": True}
                )
        
        # 4. Policy evaluation
        decision, reason, metadata = self.policy.evaluate(
            tool_name,
            agent_identity,
            capability_token,
            runtime_context,
            tool_args
        )
        
        # 5. Handle approval requirement
        if decision == PolicyDecision.REQUIRE_APPROVAL:
            policy = self.policy.get_policy(tool_name)
            request_id = self.approval_system.request_approval(
                tool_name,
                agent_identity.agent_id,
                tool_args,
                reason,
                runtime_context.risk_score,
                policy.approval_type if policy else "single"
            )
            metadata["approval_request_id"] = request_id
            reason = f"Awaiting human approval (request: {request_id})"
        
        # 6. Track successful call
        if decision == PolicyDecision.ALLOW or decision == PolicyDecision.ALLOW_WITH_SANITIZATION:
            runtime_context.add_tool_call(tool_name)
            self._update_rate_limit(agent_identity.agent_id, tool_name)
        
        # 7. Audit log
        self.audit_logger.log(
            agent_identity.agent_id,
            tool_name,
            "check_tool_call",
            decision,
            reason,
            tool_args,
            capability_token,
            runtime_context,
            metadata
        )
        
        # 8. Return result
        return self._create_result(decision, reason, tool_name, metadata)
    
    def _calculate_risk_score(
        self,
        agent_identity: AgentIdentity,
        tool_name: str,
        tool_args: Dict[str, Any],
        runtime_context: RuntimeContext
    ) -> float:
        """
        Calculate risk score for anomaly detection (0.0 to 1.0).
        Higher score = higher risk.
        """
        risk_score = 0.0
        
        # Factor 1: Identity trust (inverse - lower trust = higher risk)
        trust_score = agent_identity.get_trust_score()
        risk_score += (1.0 - trust_score) * 0.3
        
        # Factor 2: Tool sensitivity
        policy = self.policy.get_policy(tool_name)
        if policy:
            sensitivity_risk = {
                ToolSensitivity.PUBLIC_READ: 0.0,
                ToolSensitivity.INTERNAL_READ: 0.1,
                ToolSensitivity.INTERNAL_WRITE: 0.3,
                ToolSensitivity.SENSITIVE_WRITE: 0.6,
                ToolSensitivity.PRIVILEGED_ADMIN: 0.8,
                ToolSensitivity.EXTERNAL_CREDENTIAL: 0.7
            }
            risk_score += sensitivity_risk.get(policy.sensitivity, 0.5) * 0.3
        
        # Factor 3: Unusual tool call patterns
        recent_calls = runtime_context.recent_tool_calls
        if len(recent_calls) > 0:
            # Rapid successive calls to same tool
            same_tool_count = recent_calls[-10:].count(tool_name)
            if same_tool_count > 5:
                risk_score += 0.2
            
            # Diverse tool calls in short time (possible privilege escalation)
            unique_tools = len(set(recent_calls[-20:]))
            if unique_tools > 10:
                risk_score += 0.15
        
        # Factor 4: Unusual arguments
        if self._has_suspicious_args(tool_args):
            risk_score += 0.1
        
        return min(1.0, risk_score)
    
    def _has_suspicious_args(self, tool_args: Dict[str, Any]) -> bool:
        """Detect potentially suspicious argument patterns"""
        suspicious_patterns = [
            r'<script',
            r'javascript:',
            r'\.\./\.\.',
            r'DROP\s+TABLE',
            r'SELECT\s+\*\s+FROM',
            r'eval\(',
            r'exec\(',
        ]
        
        args_str = json.dumps(tool_args).lower()
        return any(re.search(pattern, args_str, re.IGNORECASE) for pattern in suspicious_patterns)
    
    def _check_rate_limit(self, agent_id: str, tool_name: str) -> bool:
        """Check if rate limit is exceeded"""
        key = f"{agent_id}:{tool_name}"
        now = datetime.utcnow()
        
        # Initialize if needed
        if key not in self.rate_limit_counters:
            self.rate_limit_counters[key] = []
        
        # Clean old entries (beyond 1 hour)
        cutoff = now - timedelta(hours=1)
        self.rate_limit_counters[key] = [
            ts for ts in self.rate_limit_counters[key]
            if ts > cutoff
        ]
        
        # Check policy limit
        policy = self.policy.get_policy(tool_name)
        if policy and policy.max_invocations_per_hour:
            if len(self.rate_limit_counters[key]) >= policy.max_invocations_per_hour:
                return False
        
        return True
    
    def _update_rate_limit(self, agent_id: str, tool_name: str):
        """Update rate limit counter after successful call"""
        key = f"{agent_id}:{tool_name}"
        if key not in self.rate_limit_counters:
            self.rate_limit_counters[key] = []
        self.rate_limit_counters[key].append(datetime.utcnow())
    
    def _create_result(
        self,
        decision: PolicyDecision,
        reason: str,
        tool_name: str,
        metadata: Dict[str, Any]
    ) -> GuardrailResult:
        """Convert PolicyDecision to GuardrailResult"""
        
        # Map PolicyDecision to GuardrailAction
        action_map = {
            PolicyDecision.ALLOW: GuardrailAction.ALLOW,
            PolicyDecision.DENY: GuardrailAction.BLOCK,
            PolicyDecision.REQUIRE_APPROVAL: GuardrailAction.BLOCK,
            PolicyDecision.ALLOW_WITH_SANITIZATION: GuardrailAction.MODIFY,
            PolicyDecision.AUDIT_ONLY: GuardrailAction.WARN,
            PolicyDecision.QUARANTINE: GuardrailAction.BLOCK
        }
        
        # Map PolicyDecision to severity
        severity_map = {
            PolicyDecision.ALLOW: GuardrailSeverity.INFO,
            PolicyDecision.DENY: GuardrailSeverity.ERROR,
            PolicyDecision.REQUIRE_APPROVAL: GuardrailSeverity.WARNING,
            PolicyDecision.ALLOW_WITH_SANITIZATION: GuardrailSeverity.WARNING,
            PolicyDecision.AUDIT_ONLY: GuardrailSeverity.INFO,
            PolicyDecision.QUARANTINE: GuardrailSeverity.CRITICAL
        }
        
        passed = decision in [PolicyDecision.ALLOW, PolicyDecision.ALLOW_WITH_SANITIZATION, PolicyDecision.AUDIT_ONLY]
        
        return GuardrailResult(
            passed=passed,
            action=action_map[decision],
            severity=severity_map[decision],
            message=f"Tool '{tool_name}': {reason}",
            metadata={
                **metadata,
                "decision": decision.value,
                "tool_name": tool_name
            }
        )
    
    def get_policy_summary(self) -> Dict[str, Any]:
        """Get summary of access control policy"""
        return {
            "guardrail_name": self.name,
            "policy_version": self.policy.version,
            "registered_tools": len(self.policy.policies),
            "tools": {
                name: {
                    "sensitivity": policy.sensitivity.value,
                    "requires_approval": policy.requires_approval,
                    "allowed_roles": [r.value for r in policy.allowed_roles]
                }
                for name, policy in self.policy.policies.items()
            },
            "audit_entries": len(self.audit_logger.entries),
            "pending_approvals": len(self.approval_system.pending_approvals),
            "configuration": {
                "anomaly_detection_enabled": self.enable_anomaly_detection,
                "anomaly_threshold": self.anomaly_threshold,
                "rate_limiting_enabled": self.enable_rate_limiting
            }
        }
    
    def generate_capability_token(
        self,
        agent_id: str,
        tool_name: str,
        allowed_actions: List[ToolAction],
        constraints: Dict[str, Any],
        validity_hours: int = 1,
        session_id: Optional[str] = None
    ) -> CapabilityToken:
        """
        Generate a new capability token for an agent.
        In production, this would be handled by a separate authority service.
        """
        import secrets
        
        now = datetime.utcnow()
        token_id = secrets.token_hex(16)
        nonce = secrets.token_hex(8)
        
        token = CapabilityToken(
            token_id=token_id,
            agent_id=agent_id,
            tool_name=tool_name,
            allowed_actions=allowed_actions,
            constraints=constraints,
            issued_at=now,
            expires_at=now + timedelta(hours=validity_hours),
            session_id=session_id,
            nonce=nonce
        )
        
        # Sign token
        payload = f"{token.token_id}:{token.agent_id}:{token.tool_name}:{token.issued_at.isoformat()}"
        token.signature = hashlib.sha256(f"{payload}:{self.signing_key}".encode()).hexdigest()
        
        return token


# ============================================================================
# 7. EXAMPLE CONFIGURATIONS
# ============================================================================

def create_production_tool_access_guardrail() -> ToolAccessControlGuardrail:
    """
    Create a production-ready tool access control guardrail with strict policies.
    """
    
    # Initialize policy
    policy = ToolAccessPolicy()
    
    # Register common tools with policies
    
    # Financial transfer tool - HIGHLY SENSITIVE
    policy.register_tool(ToolPolicy(
        tool_name="finance.transfer",
        sensitivity=ToolSensitivity.SENSITIVE_WRITE,
        allowed_roles={AgentRole.ORCHESTRATOR, AgentRole.ADMIN},
        required_identity_strength=IdentityStrength.MFA_VERIFIED,
        requires_approval=True,
        approval_type="multi",
        max_invocations_per_hour=10,
        input_sanitization_required=True,
        audit_required=True
    ))
    
    # Database query tool - INTERNAL READ
    policy.register_tool(ToolPolicy(
        tool_name="database.query",
        sensitivity=ToolSensitivity.INTERNAL_READ,
        allowed_roles={AgentRole.TASK_ONLY, AgentRole.ASSISTANT, AgentRole.ORCHESTRATOR, AgentRole.ADMIN},
        required_identity_strength=IdentityStrength.EMAIL_VERIFIED,
        requires_approval=False,
        max_invocations_per_hour=100,
        output_redaction_required=True,
        audit_required=True
    ))
    
    # Email send tool - INTERNAL WRITE
    policy.register_tool(ToolPolicy(
        tool_name="email.send",
        sensitivity=ToolSensitivity.INTERNAL_WRITE,
        allowed_roles={AgentRole.ASSISTANT, AgentRole.ORCHESTRATOR, AgentRole.ADMIN},
        required_identity_strength=IdentityStrength.EMAIL_VERIFIED,
        requires_approval=False,
        max_invocations_per_hour=50,
        input_sanitization_required=True,
        audit_required=True
    ))
    
    # Secrets vault access - EXTERNAL CREDENTIAL
    policy.register_tool(ToolPolicy(
        tool_name="vault.get_secret",
        sensitivity=ToolSensitivity.EXTERNAL_CREDENTIAL,
        allowed_roles={AgentRole.ADMIN},
        required_identity_strength=IdentityStrength.DEVICE_ATTESTED,
        requires_approval=True,
        approval_type="single",
        max_invocations_per_hour=5,
        output_redaction_required=True,
        audit_required=True
    ))
    
    # Web search tool - PUBLIC READ
    policy.register_tool(ToolPolicy(
        tool_name="web.search",
        sensitivity=ToolSensitivity.PUBLIC_READ,
        allowed_roles={AgentRole.TASK_ONLY, AgentRole.ASSISTANT, AgentRole.ORCHESTRATOR},
        required_identity_strength=IdentityStrength.UNVERIFIED,
        requires_approval=False,
        max_invocations_per_hour=1000,
        audit_required=False
    ))
    
    # Add global rule: Block all unregistered tools
    def block_unregistered_tools(tool_name, agent_identity, runtime_context, tool_args):
        if tool_name not in policy.policies:
            return PolicyDecision.DENY, f"Tool '{tool_name}' is not registered"
        return PolicyDecision.ALLOW, ""
    
    policy.add_global_rule(block_unregistered_tools)
    
    # Create guardrail
    guardrail = ToolAccessControlGuardrail(
        name="ProductionToolAccessControl",
        policy=policy,
        approval_system=ApprovalSystem(),
        audit_logger=AuditLogger(),
        signing_key="CHANGE_THIS_IN_PRODUCTION_USE_HSM",
        enable_anomaly_detection=True,
        anomaly_threshold=0.75,
        enable_rate_limiting=True
    )
    
    return guardrail


def create_development_tool_access_guardrail() -> ToolAccessControlGuardrail:
    """
    Create a more permissive tool access control guardrail for development.
    """
    
    policy = ToolAccessPolicy()
    
    # More permissive policies for development
    policy.register_tool(ToolPolicy(
        tool_name="database.query",
        sensitivity=ToolSensitivity.INTERNAL_READ,
        allowed_roles={AgentRole.TASK_ONLY, AgentRole.ASSISTANT, AgentRole.ORCHESTRATOR, AgentRole.ADMIN},
        required_identity_strength=IdentityStrength.UNVERIFIED,
        requires_approval=False,
        max_invocations_per_hour=500,
        allowed_environments={"development", "staging"}
    ))
    
    guardrail = ToolAccessControlGuardrail(
        name="DevelopmentToolAccessControl",
        policy=policy,
        enable_anomaly_detection=False,
        enable_rate_limiting=False
    )
    
    return guardrail


# ============================================================================
# 8. USAGE EXAMPLE
# ============================================================================

def example_usage():
    """
    Example usage of the tool access control guardrail.
    """
    
    # 1. Create guardrail
    guardrail = create_production_tool_access_guardrail()
    
    # 2. Create agent identity
    agent = AgentIdentity(
        agent_id="agent_12345",
        agent_type=PrincipalType.AGENT,
        agent_role=AgentRole.ASSISTANT,
        owner_team="engineering",
        purpose="Customer support assistant",
        creation_time=datetime.utcnow(),
        identity_strength=IdentityStrength.EMAIL_VERIFIED,
        attestation_signature="valid_signature_here"
    )
    
    # 3. Generate capability token
    capability = guardrail.generate_capability_token(
        agent_id=agent.agent_id,
        tool_name="database.query",
        allowed_actions=[ToolAction.READ],
        constraints={"max_rows": 100},
        validity_hours=1,
        session_id="session_abc"
    )
    
    # 4. Create runtime context
    runtime_ctx = RuntimeContext(
        session_id="session_abc",
        user_identity="user_789",
        user_verified=True,
        environment="production"
    )
    
    # 5. Check tool call
    result = guardrail.check_tool_call(
        tool_name="database.query",
        tool_args={"query": "SELECT * FROM users LIMIT 50"},
        context={
            "agent_identity": agent,
            "capability_token": capability,
            "runtime_context": runtime_ctx
        }
    )
    
    print(f"Tool call allowed: {result.passed}")
    print(f"Action: {result.action.value}")
    print(f"Message: {result.message}")
    print(f"Metadata: {json.dumps(result.metadata, indent=2)}")
    
    # 6. Get policy summary
    summary = guardrail.get_policy_summary()
    print(f"\nPolicy Summary:\n{json.dumps(summary, indent=2)}")


if __name__ == "__main__":
    example_usage()