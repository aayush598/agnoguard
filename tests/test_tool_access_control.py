# tests/test_tool_access_control.py
"""
Comprehensive test suite for tool access control guardrails.

Tests cover:
- Identity and attestation
- Capability token generation and verification
- Policy evaluation logic
- Approval workflows
- Audit logging
- Anomaly detection
- Rate limiting
- Edge cases and security scenarios
"""

import pytest
import hashlib
import json
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List

# Import the guardrail components
# Adjust imports based on your actual package structure
from agnoguard.guardrails.tool_access_control import (
    # Enums
    ToolSensitivity,
    ToolAction,
    PrincipalType,
    IdentityStrength,
    AgentRole,
    PolicyDecision,

    # Data classes
    AgentIdentity,
    CapabilityToken,
    RuntimeContext,
    ToolPolicy,
    ApprovalRequest,
    AuditEntry,

    # Main classes
    ToolAccessPolicy,
    ApprovalSystem,
    AuditLogger,
    ToolAccessControlGuardrail,

    # Factory functions
    create_production_tool_access_guardrail,
    create_development_tool_access_guardrail,
)

from agnoguard.core.base import GuardrailAction, GuardrailSeverity


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def basic_agent_identity():
    """Create a basic agent identity for testing"""
    return AgentIdentity(
        agent_id="test_agent_001",
        agent_type=PrincipalType.AGENT,
        agent_role=AgentRole.ASSISTANT,
        owner_team="test_team",
        purpose="Testing agent",
        creation_time=datetime.utcnow(),
        identity_strength=IdentityStrength.EMAIL_VERIFIED,
        attestation_signature="test_signature"
    )


@pytest.fixture
def high_privilege_agent_identity():
    """Create a high-privilege agent identity"""
    return AgentIdentity(
        agent_id="admin_agent_001",
        agent_type=PrincipalType.AGENT,
        agent_role=AgentRole.ADMIN,
        owner_team="admin_team",
        purpose="Administrative agent",
        creation_time=datetime.utcnow(),
        identity_strength=IdentityStrength.DEVICE_ATTESTED,
        attestation_signature="admin_signature"
    )


@pytest.fixture
def low_privilege_agent_identity():
    """Create a low-privilege agent identity"""
    return AgentIdentity(
        agent_id="task_agent_001",
        agent_type=PrincipalType.AGENT,
        agent_role=AgentRole.TASK_ONLY,
        owner_team="test_team",
        purpose="Task-specific agent",
        creation_time=datetime.utcnow(),
        identity_strength=IdentityStrength.UNVERIFIED,
        attestation_signature=None
    )


@pytest.fixture
def runtime_context():
    """Create a basic runtime context"""
    return RuntimeContext(
        session_id="test_session_001",
        user_identity="test_user_001",
        user_verified=True,
        environment="production",
        geo_location="US"
    )


@pytest.fixture
def tool_policy():
    """Create a basic tool policy"""
    return ToolAccessPolicy()


@pytest.fixture
def approval_system():
    """Create an approval system"""
    return ApprovalSystem()


@pytest.fixture
def audit_logger():
    """Create an audit logger"""
    return AuditLogger()


@pytest.fixture
def signing_key():
    """Signing key for capability tokens"""
    return "test_signing_key_do_not_use_in_production"


@pytest.fixture
def guardrail(tool_policy, approval_system, audit_logger, signing_key):
    """Create a configured guardrail"""

    # Register some test tools
    tool_policy.register_tool(ToolPolicy(
        tool_name="test.read",
        sensitivity=ToolSensitivity.INTERNAL_READ,
        allowed_roles={AgentRole.TASK_ONLY, AgentRole.ASSISTANT, AgentRole.ADMIN},
        required_identity_strength=IdentityStrength.UNVERIFIED,
        requires_approval=False,
        max_invocations_per_hour=100
    ))

    tool_policy.register_tool(ToolPolicy(
        tool_name="test.write",
        sensitivity=ToolSensitivity.INTERNAL_WRITE,
        allowed_roles={AgentRole.ASSISTANT, AgentRole.ADMIN},
        required_identity_strength=IdentityStrength.EMAIL_VERIFIED,
        requires_approval=False,
        max_invocations_per_hour=50
    ))

    tool_policy.register_tool(ToolPolicy(
        tool_name="test.sensitive",
        sensitivity=ToolSensitivity.SENSITIVE_WRITE,
        allowed_roles={AgentRole.ADMIN},
        required_identity_strength=IdentityStrength.MFA_VERIFIED,
        requires_approval=True,
        approval_type="multi",
        max_invocations_per_hour=10
    ))

    return ToolAccessControlGuardrail(
        name="TestGuardrail",
        policy=tool_policy,
        approval_system=approval_system,
        audit_logger=audit_logger,
        signing_key=signing_key,
        enable_anomaly_detection=True,
        enable_rate_limiting=True
    )


# ============================================================================
# TEST: AgentIdentity
# ============================================================================

class TestAgentIdentity:
    """Test AgentIdentity functionality"""

    def test_agent_identity_creation(self, basic_agent_identity):
        """Test basic agent identity creation"""
        assert basic_agent_identity.agent_id == "test_agent_001"
        assert basic_agent_identity.agent_role == AgentRole.ASSISTANT
        assert basic_agent_identity.identity_strength == IdentityStrength.EMAIL_VERIFIED

    def test_agent_attestation_check(self, basic_agent_identity):
        """Test attestation verification"""
        assert basic_agent_identity.is_attested() is True

        unattested = AgentIdentity(
            agent_id="no_attest",
            agent_type=PrincipalType.AGENT,
            agent_role=AgentRole.TASK_ONLY,
            owner_team="test",
            purpose="test",
            creation_time=datetime.utcnow(),
            identity_strength=IdentityStrength.UNVERIFIED
        )
        assert unattested.is_attested() is False

    def test_trust_score_calculation(self, basic_agent_identity, high_privilege_agent_identity):
        """Test trust score calculation"""
        basic_score = basic_agent_identity.get_trust_score()
        high_score = high_privilege_agent_identity.get_trust_score()

        # High privilege should have higher trust score
        assert high_score > basic_score

        # Trust scores should be in valid range
        assert 0.0 <= basic_score <= 1.0
        assert 0.0 <= high_score <= 1.0

    def test_trust_score_with_attestation(self):
        """Test that attestation increases trust score"""
        without_attestation = AgentIdentity(
            agent_id="no_attest",
            agent_type=PrincipalType.AGENT,
            agent_role=AgentRole.ASSISTANT,
            owner_team="test",
            purpose="test",
            creation_time=datetime.utcnow(),
            identity_strength=IdentityStrength.EMAIL_VERIFIED,
            attestation_signature=None
        )

        with_attestation = AgentIdentity(
            agent_id="with_attest",
            agent_type=PrincipalType.AGENT,
            agent_role=AgentRole.ASSISTANT,
            owner_team="test",
            purpose="test",
            creation_time=datetime.utcnow(),
            identity_strength=IdentityStrength.EMAIL_VERIFIED,
            attestation_signature="valid_sig"
        )

        assert with_attestation.get_trust_score() > without_attestation.get_trust_score()


# ============================================================================
# TEST: CapabilityToken
# ============================================================================

class TestCapabilityToken:
    """Test CapabilityToken functionality"""

    def test_capability_token_creation(self):
        """Test capability token creation"""
        now = datetime.utcnow()
        token = CapabilityToken(
            token_id="token_001",
            agent_id="agent_001",
            tool_name="test.tool",
            allowed_actions=[ToolAction.READ, ToolAction.INVOKE],
            constraints={"max_amount": 1000},
            issued_at=now,
            expires_at=now + timedelta(hours=1),
            session_id="session_001",
            nonce="nonce123"
        )

        assert token.token_id == "token_001"
        assert ToolAction.READ in token.allowed_actions
        assert token.constraints["max_amount"] == 1000

    def test_token_validity(self):
        """Test token validity checks"""
        now = datetime.utcnow()

        # Valid token
        valid_token = CapabilityToken(
            token_id="valid",
            agent_id="agent",
            tool_name="tool",
            allowed_actions=[ToolAction.INVOKE],
            constraints={},
            issued_at=now - timedelta(minutes=30),
            expires_at=now + timedelta(minutes=30)
        )
        assert valid_token.is_valid() is True
        assert valid_token.is_expired() is False

        # Expired token
        expired_token = CapabilityToken(
            token_id="expired",
            agent_id="agent",
            tool_name="tool",
            allowed_actions=[ToolAction.INVOKE],
            constraints={},
            issued_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1)
        )
        assert expired_token.is_valid() is False
        assert expired_token.is_expired() is True

    def test_token_signature_verification(self, signing_key):
        """Test capability token signature verification"""
        now = datetime.utcnow()
        token = CapabilityToken(
            token_id="token_sig",
            agent_id="agent_sig",
            tool_name="tool.test",
            allowed_actions=[ToolAction.INVOKE],
            constraints={},
            issued_at=now,
            expires_at=now + timedelta(hours=1)
        )

        # Generate signature
        payload = f"{token.token_id}:{token.agent_id}:{token.tool_name}:{token.issued_at.isoformat()}"
        token.signature = hashlib.sha256(f"{payload}:{signing_key}".encode()).hexdigest()

        # Verify with correct key
        assert token.verify_signature(signing_key) is True

        # Verify with wrong key
        assert token.verify_signature("wrong_key") is False

    def test_action_permission_check(self):
        """Test action permission checking"""
        token = CapabilityToken(
            token_id="token",
            agent_id="agent",
            tool_name="tool",
            allowed_actions=[ToolAction.READ, ToolAction.INVOKE],
            constraints={},
            issued_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )

        assert token.allows_action(ToolAction.READ) is True
        assert token.allows_action(ToolAction.INVOKE) is True
        assert token.allows_action(ToolAction.WRITE) is False
        assert token.allows_action(ToolAction.DELETE) is False

    def test_constraint_validation_amount(self):
        """Test amount constraint validation"""
        token = CapabilityToken(
            token_id="token",
            agent_id="agent",
            tool_name="finance.transfer",
            allowed_actions=[ToolAction.WRITE],
            constraints={"max_amount": 1000},
            issued_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )

        # Within limit
        passed, error = token.check_constraints({"amount": 500})
        assert passed is True
        assert error is None

        # Exceeds limit
        passed, error = token.check_constraints({"amount": 2000})
        assert passed is False
        assert "exceeds maximum" in error

    def test_constraint_validation_pattern(self):
        """Test pattern constraint validation"""
        token = CapabilityToken(
            token_id="token",
            agent_id="agent",
            tool_name="finance.transfer",
            allowed_actions=[ToolAction.WRITE],
            constraints={"dest_account_pattern": r"^internal_.*$"},
            issued_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )

        # Matches pattern
        passed, error = token.check_constraints({"dest_account": "internal_acct_123"})
        assert passed is True

        # Doesn't match pattern
        passed, error = token.check_constraints({"dest_account": "external_acct_456"})
        assert passed is False
        assert "does not match allowed pattern" in error

    def test_constraint_validation_allowed_values(self):
        """Test allowed values constraint"""
        token = CapabilityToken(
            token_id="token",
            agent_id="agent",
            tool_name="database.query",
            allowed_actions=[ToolAction.READ],
            constraints={"allowed_database": ["users", "orders", "products"]},
            issued_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )

        # Allowed value
        passed, error = token.check_constraints({"database": "users"})
        assert passed is True

        # Disallowed value
        passed, error = token.check_constraints({"database": "admin"})
        assert passed is False
        assert "not in allowed set" in error


# ============================================================================
# TEST: ToolAccessPolicy
# ============================================================================

class TestToolAccessPolicy:
    """Test ToolAccessPolicy functionality"""

    def test_policy_registration(self, tool_policy):
        """Test tool policy registration"""
        policy = ToolPolicy(
            tool_name="new.tool",
            sensitivity=ToolSensitivity.INTERNAL_READ,
            allowed_roles={AgentRole.ASSISTANT},
            required_identity_strength=IdentityStrength.EMAIL_VERIFIED
        )

        tool_policy.register_tool(policy)

        retrieved = tool_policy.get_policy("new.tool")
        assert retrieved is not None
        assert retrieved.tool_name == "new.tool"
        assert retrieved.sensitivity == ToolSensitivity.INTERNAL_READ

    def test_policy_evaluation_allowed(
        self,
        tool_policy,
        basic_agent_identity,
        runtime_context
    ):
        """Test policy evaluation - allowed case"""

        # Register tool
        tool_policy.register_tool(ToolPolicy(
            tool_name="allowed.tool",
            sensitivity=ToolSensitivity.INTERNAL_READ,
            allowed_roles={AgentRole.ASSISTANT},
            required_identity_strength=IdentityStrength.EMAIL_VERIFIED
        ))

        # Create capability token
        now = datetime.utcnow()
        token = CapabilityToken(
            token_id="token",
            agent_id=basic_agent_identity.agent_id,
            tool_name="allowed.tool",
            allowed_actions=[ToolAction.READ],
            constraints={},
            issued_at=now,
            expires_at=now + timedelta(hours=1)
        )

        decision, reason, metadata = tool_policy.evaluate(
            "allowed.tool",
            basic_agent_identity,
            token,
            runtime_context,
            {}
        )

        assert decision == PolicyDecision.ALLOW
        assert "passed" in reason.lower()

    def test_policy_evaluation_wrong_role(
        self,
        tool_policy,
        low_privilege_agent_identity,
        runtime_context
    ):
        """Test policy evaluation - denied due to wrong role"""

        tool_policy.register_tool(ToolPolicy(
            tool_name="admin.tool",
            sensitivity=ToolSensitivity.PRIVILEGED_ADMIN,
            allowed_roles={AgentRole.ADMIN},
            required_identity_strength=IdentityStrength.DEVICE_ATTESTED
        ))

        now = datetime.utcnow()
        token = CapabilityToken(
            token_id="token",
            agent_id=low_privilege_agent_identity.agent_id,
            tool_name="admin.tool",
            allowed_actions=[ToolAction.INVOKE],
            constraints={},
            issued_at=now,
            expires_at=now + timedelta(hours=1)
        )

        decision, reason, metadata = tool_policy.evaluate(
            "admin.tool",
            low_privilege_agent_identity,
            token,
            runtime_context,
            {}
        )

        assert decision == PolicyDecision.DENY
        assert "not authorized" in reason.lower()

    def test_policy_evaluation_insufficient_identity(
        self,
        tool_policy,
        low_privilege_agent_identity,
        runtime_context
    ):
        """Test policy evaluation - denied due to insufficient identity strength"""

        tool_policy.register_tool(ToolPolicy(
            tool_name="secure.tool",
            sensitivity=ToolSensitivity.SENSITIVE_WRITE,
            allowed_roles={AgentRole.TASK_ONLY, AgentRole.ASSISTANT},
            required_identity_strength=IdentityStrength.MFA_VERIFIED
        ))

        now = datetime.utcnow()
        token = CapabilityToken(
            token_id="token",
            agent_id=low_privilege_agent_identity.agent_id,
            tool_name="secure.tool",
            allowed_actions=[ToolAction.WRITE],
            constraints={},
            issued_at=now,
            expires_at=now + timedelta(hours=1)
        )

        decision, reason, metadata = tool_policy.evaluate(
            "secure.tool",
            low_privilege_agent_identity,
            token,
            runtime_context,
            {}
        )

        assert decision == PolicyDecision.DENY
        assert "identity strength" in reason.lower()

    def test_policy_evaluation_no_token(
        self,
        tool_policy,
        basic_agent_identity,
        runtime_context
    ):
        """Test policy evaluation - denied due to missing token"""

        tool_policy.register_tool(ToolPolicy(
            tool_name="test.tool",
            sensitivity=ToolSensitivity.INTERNAL_READ,
            allowed_roles={AgentRole.ASSISTANT},
            required_identity_strength=IdentityStrength.EMAIL_VERIFIED
        ))

        decision, reason, metadata = tool_policy.evaluate(
            "test.tool",
            basic_agent_identity,
            None,  # No token
            runtime_context,
            {}
        )

        assert decision == PolicyDecision.DENY
        assert "token" in reason.lower()

    def test_policy_evaluation_expired_token(
        self,
        tool_policy,
        basic_agent_identity,
        runtime_context
    ):
        """Test policy evaluation - denied due to expired token"""

        tool_policy.register_tool(ToolPolicy(
            tool_name="test.tool",
            sensitivity=ToolSensitivity.INTERNAL_READ,
            allowed_roles={AgentRole.ASSISTANT},
            required_identity_strength=IdentityStrength.EMAIL_VERIFIED
        ))

        # Expired token
        now = datetime.utcnow()
        token = CapabilityToken(
            token_id="expired",
            agent_id=basic_agent_identity.agent_id,
            tool_name="test.tool",
            allowed_actions=[ToolAction.READ],
            constraints={},
            issued_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1)
        )

        decision, reason, metadata = tool_policy.evaluate(
            "test.tool",
            basic_agent_identity,
            token,
            runtime_context,
            {}
        )

        assert decision == PolicyDecision.DENY
        assert "expired" in reason.lower() or "invalid" in reason.lower()

    def test_policy_evaluation_requires_approval(
        self,
        tool_policy,
        high_privilege_agent_identity,
        runtime_context
    ):
        """Test policy evaluation - requires approval"""

        tool_policy.register_tool(ToolPolicy(
            tool_name="approval.required",
            sensitivity=ToolSensitivity.SENSITIVE_WRITE,
            allowed_roles={AgentRole.ADMIN},
            required_identity_strength=IdentityStrength.DEVICE_ATTESTED,
            requires_approval=True,
            approval_type="multi"
        ))

        now = datetime.utcnow()
        token = CapabilityToken(
            token_id="token",
            agent_id=high_privilege_agent_identity.agent_id,
            tool_name="approval.required",
            allowed_actions=[ToolAction.WRITE],
            constraints={},
            issued_at=now,
            expires_at=now + timedelta(hours=1)
        )

        decision, reason, metadata = tool_policy.evaluate(
            "approval.required",
            high_privilege_agent_identity,
            token,
            runtime_context,
            {}
        )

        assert decision == PolicyDecision.REQUIRE_APPROVAL
        assert "approval" in reason.lower()
        assert metadata.get("approval_type") == "multi"

    def test_policy_evaluation_rate_limit(
        self,
        tool_policy,
        basic_agent_identity,
        runtime_context
    ):
        """Test policy evaluation - rate limit check"""

        tool_policy.register_tool(ToolPolicy(
            tool_name="rate.limited",
            sensitivity=ToolSensitivity.INTERNAL_READ,
            allowed_roles={AgentRole.ASSISTANT},
            required_identity_strength=IdentityStrength.EMAIL_VERIFIED,
            max_invocations_per_hour=5
        ))

        now = datetime.utcnow()
        token = CapabilityToken(
            token_id="token",
            agent_id=basic_agent_identity.agent_id,
            tool_name="rate.limited",
            allowed_actions=[ToolAction.READ],
            constraints={},
            issued_at=now,
            expires_at=now + timedelta(hours=1)
        )

        # Simulate 5 calls
        runtime_context.rate_limit_state["rate.limited:test_agent_001"] = 5

        decision, reason, metadata = tool_policy.evaluate(
            "rate.limited",
            basic_agent_identity,
            token,
            runtime_context,
            {}
        )

        assert decision == PolicyDecision.DENY
        assert "rate limit" in reason.lower()


# ============================================================================
# TEST: ApprovalSystem
# ============================================================================

class TestApprovalSystem:
    """Test ApprovalSystem functionality"""

    def test_approval_request_creation(self, approval_system):
        """Test creating an approval request"""
        request_id = approval_system.request_approval(
            tool_name="finance.transfer",
            agent_id="agent_123",
            tool_args={"amount": 5000, "dest": "external_account"},
            reason="High-value transfer",
            risk_score=0.75,
            approval_type="multi"
        )

        assert request_id is not None
        assert len(request_id) > 0
        assert request_id in approval_system.pending_approvals

        request = approval_system.pending_approvals[request_id]
        assert request.tool_name == "finance.transfer"
        assert request.agent_id == "agent_123"
        assert request.risk_score == 0.75
        assert request.status == "pending"

    def test_approval_grant(self, approval_system):
        """Test approving a request"""
        request_id = approval_system.request_approval(
            tool_name="test.tool",
            agent_id="agent_123",
            tool_args={},
            reason="Test",
            risk_score=0.5,
            approval_type="single"
        )

        result = approval_system.approve(request_id, "approver_001", "Looks good")

        assert result is True
        assert request_id not in approval_system.pending_approvals
        assert len(approval_system.approval_history) == 1
        assert approval_system.approval_history[0].status == "approved"
        assert approval_system.approval_history[0].approver_id == "approver_001"

    def test_approval_deny(self, approval_system):
        """Test denying a request"""
        request_id = approval_system.request_approval(
            tool_name="test.tool",
            agent_id="agent_123",
            tool_args={},
            reason="Test",
            risk_score=0.5,
            approval_type="single"
        )

        result = approval_system.deny(request_id, "approver_001", "Not authorized")

        assert result is True
        assert request_id not in approval_system.pending_approvals
        assert len(approval_system.approval_history) == 1
        assert approval_system.approval_history[0].status == "denied"

    def test_approval_status_check(self, approval_system):
        """Test checking approval status"""
        request_id = approval_system.request_approval(
            tool_name="test.tool",
            agent_id="agent_123",
            tool_args={},
            reason="Test",
            risk_score=0.5,
            approval_type="single"
        )

        # Pending status
        status = approval_system.get_status(request_id)
        assert status == "pending"

        # Approve and check again
        approval_system.approve(request_id, "approver_001")
        status = approval_system.get_status(request_id)
        assert status == "approved"

    def test_sensitive_arg_redaction(self, approval_system):
        """Test that sensitive args are redacted"""
        request_id = approval_system.request_approval(
            tool_name="vault.access",
            agent_id="agent_123",
            tool_args={
                "username": "user",
                "password": "secret123",
                "api_key": "key_abc123",
                "normal_field": "visible"
            },
            reason="Test",
            risk_score=0.5,
            approval_type="single"
        )

        request = approval_system.pending_approvals[request_id]

        # Sensitive fields should be redacted
        assert request.tool_args["password"] == "[REDACTED]"
        assert request.tool_args["api_key"] == "[REDACTED]"

        # Normal fields should be visible
        assert request.tool_args["username"] == "user"
        assert request.tool_args["normal_field"] == "visible"


# ============================================================================
# TEST: AuditLogger
# ============================================================================

class TestAuditLogger:
    """Test AuditLogger functionality"""

    def test_audit_entry_creation(
        self,
        audit_logger,
        basic_agent_identity,
        runtime_context
    ):
        """Test creating an audit entry"""
        now = datetime.utcnow()
        token = CapabilityToken(
            token_id="token_123",
            agent_id=basic_agent_identity.agent_id,
            tool_name="test.tool",
            allowed_actions=[ToolAction.READ],
            constraints={},
            issued_at=now,
            expires_at=now + timedelta(hours=1)
        )

        audit_logger.log(
            agent_id=basic_agent_identity.agent_id,
            tool_name="test.tool",
            action="invoke",
            decision=PolicyDecision.ALLOW,
            reason="Policy check passed",
            tool_args={"arg1": "value1"},
            capability_token=token,
            context=runtime_context,
            metadata={"additional": "info"}
        )

        assert len(audit_logger.entries) == 1
        entry = audit_logger.entries[0]

        assert entry.agent_id == basic_agent_identity.agent_id
        assert entry.tool_name == "test.tool"
        assert entry.decision == PolicyDecision.ALLOW
        assert entry.capability_token_id == "token_123"

    def test_audit_args_hashing(
        self,
        audit_logger,
        basic_agent_identity,
        runtime_context
    ):
        """Test that tool arguments are hashed, not stored in plaintext"""
        audit_logger.log(
            agent_id=basic_agent_identity.agent_id,
            tool_name="test.tool",
            action="invoke",
            decision=PolicyDecision.ALLOW,
            reason="Test",
            tool_args={"sensitive": "data", "password": "secret"},
            capability_token=None,
            context=runtime_context,
            metadata={}
        )

        entry = audit_logger.entries[0]

        # tool_args_hash should be a hex string of length 64 (sha256)
        assert isinstance(entry.tool_args_hash, str)
        assert len(entry.tool_args_hash) == 64

    def test_get_entries_for_agent(
        self,
        audit_logger,
        basic_agent_identity,
        runtime_context
    ):
        """Test retrieving audit entries for a specific agent"""

        # Log multiple entries for different agents
        for i in range(5):
            audit_logger.log(
                agent_id=f"agent_{i}",
                tool_name="test.tool",
                action="invoke",
                decision=PolicyDecision.ALLOW,
                reason="Test",
                tool_args={},
                capability_token=None,
                context=runtime_context,
                metadata={}
            )

        # Get entries for specific agent
        entries = audit_logger.get_entries_for_agent("agent_2")

        assert len(entries) == 1
        assert entries[0].agent_id == "agent_2"

    def test_get_denied_attempts(
        self,
        audit_logger,
        basic_agent_identity,
        runtime_context
    ):
        """Test retrieving denied attempts"""

        # Log allowed and denied entries
        # Create denied entries with recent timestamps and some older ones
        now = datetime.utcnow()
        # Recent denied
        audit_logger.entries.append(AuditEntry(
            entry_id="e1",
            timestamp=datetime.utcnow(),
            agent_id=basic_agent_identity.agent_id,
            tool_name="test.tool",
            action="invoke",
            decision=PolicyDecision.DENY,
            reason="Denied test",
            tool_args_hash=hashlib.sha256(b"args").hexdigest(),
            capability_token_id=None,
            context_snapshot={},
            metadata={}
        ))
        # Older denied (beyond cutoff)
        old_entry = AuditEntry(
            entry_id="e_old",
            timestamp=datetime.utcnow() - timedelta(hours=48),
            agent_id=basic_agent_identity.agent_id,
            tool_name="test.tool",
            action="invoke",
            decision=PolicyDecision.DENY,
            reason="Old denied",
            tool_args_hash=hashlib.sha256(b"old").hexdigest(),
            capability_token_id=None,
            context_snapshot={},
            metadata={}
        )
        audit_logger.entries.append(old_entry)

        denied_last_24 = audit_logger.get_denied_attempts(hours=24)
        # Should only include the recent denied (e1)
        assert any(e.entry_id == "e1" for e in denied_last_24)
        assert all(e.timestamp >= datetime.utcnow() - timedelta(hours=24) for e in denied_last_24)


# ============================================================================
# TEST: ToolAccessControlGuardrail (integration)
# ============================================================================

class TestToolAccessControlGuardrail:
    """Integration tests for the guardrail check flow"""

    def test_check_tool_call_no_context(self, guardrail):
        """No context results in deny"""
        result = guardrail.check_tool_call("test.read", {"q": "select 1"}, context=None)
        assert result.action == GuardrailAction.BLOCK
        assert result.severity == GuardrailSeverity.ERROR
        assert "no context provided" in result.message.lower()

    def test_check_tool_call_missing_identity(self, guardrail, runtime_context):
        """Missing agent identity results in deny"""
        context = {"runtime_context": runtime_context}
        result = guardrail.check_tool_call("test.read", {"q": "select"}, context=context)
        assert result.action == GuardrailAction.BLOCK
        assert "invalid or missing agent identity" in result.message.lower()

    def test_check_tool_call_invalid_runtime_context(self, guardrail, basic_agent_identity):
        """Missing runtime context results in deny"""
        context = {"agent_identity": basic_agent_identity}
        result = guardrail.check_tool_call("test.read", {"q": "select"}, context=context)
        assert result.action == GuardrailAction.BLOCK
        assert "invalid or missing runtime context" in result.message.lower()

    def test_check_tool_call_invalid_token_signature(self, guardrail, basic_agent_identity, runtime_context, signing_key):
        """Invalid token signature should be denied and audited"""
        now = datetime.utcnow()
        token = CapabilityToken(
            token_id="tk_invalid_sig",
            agent_id=basic_agent_identity.agent_id,
            tool_name="test.read",
            allowed_actions=[ToolAction.READ],
            constraints={},
            issued_at=now,
            expires_at=now + timedelta(hours=1),
            signature="bad_signature"
        )

        context = {
            "agent_identity": basic_agent_identity,
            "capability_token": token,
            "runtime_context": runtime_context
        }

        result = guardrail.check_tool_call("test.read", {"q": "select"}, context=context)
        assert result.action == GuardrailAction.BLOCK
        assert "invalid capability token signature" in result.message.lower()

    def test_check_tool_call_allow(self, guardrail, basic_agent_identity, runtime_context):
        """Valid flow should allow the tool call"""
        # Generate a valid token using guardrail helper
        token = guardrail.generate_capability_token(
            agent_id=basic_agent_identity.agent_id,
            tool_name="test.read",
            allowed_actions=[ToolAction.READ],
            constraints={},
            validity_hours=1,
            session_id=runtime_context.session_id
        )

        # Ensure signature verifies against guardrail signing key
        assert token.verify_signature(guardrail.signing_key)

        context = {
            "agent_identity": basic_agent_identity,
            "capability_token": token,
            "runtime_context": runtime_context
        }

        result = guardrail.check_tool_call("test.read", {"query": "SELECT 1"}, context=context)
        assert result.action == GuardrailAction.ALLOW
        assert result.passed is True
        assert "passed" in result.message.lower()

    def test_requires_approval_creates_request(self, guardrail, high_privilege_agent_identity, runtime_context):
        """Requests that require approval should create an approval request"""
        # Create token for sensitive tool
        token = guardrail.generate_capability_token(
            agent_id=high_privilege_agent_identity.agent_id,
            tool_name="test.sensitive",
            allowed_actions=[ToolAction.WRITE],
            constraints={},
            validity_hours=1,
            session_id=runtime_context.session_id
        )

        context = {
            "agent_identity": high_privilege_agent_identity,
            "capability_token": token,
            "runtime_context": runtime_context
        }

        result = guardrail.check_tool_call("test.sensitive", {"operation": "do_it"}, context=context)
        # Should block pending approval
        assert result.action == GuardrailAction.BLOCK
        assert "awaiting human approval" in result.message.lower()
        metadata = result.metadata
        assert "approval_request_id" in metadata
        req_id = metadata["approval_request_id"]
        assert req_id in guardrail.approval_system.pending_approvals

    def test_rate_limit_exceeded(self, guardrail, basic_agent_identity, runtime_context):
        """Ensure rate limiting blocks when exceeded"""
        # Reduce limit for test
        guardrail.policy.policies["test.write"].max_invocations_per_hour = 1

        token = guardrail.generate_capability_token(
            agent_id=basic_agent_identity.agent_id,
            tool_name="test.write",
            allowed_actions=[ToolAction.WRITE],
            constraints={},
            validity_hours=1,
            session_id=runtime_context.session_id
        )

        context = {
            "agent_identity": basic_agent_identity,
            "capability_token": token,
            "runtime_context": runtime_context
        }

        # First call should be allowed
        r1 = guardrail.check_tool_call("test.write", {"payload": "x"}, context=context)
        assert r1.action == GuardrailAction.ALLOW

        # Immediately a second call should be blocked by internal rate limiter
        r2 = guardrail.check_tool_call("test.write", {"payload": "y"}, context=context)
        assert r2.action == GuardrailAction.BLOCK
        assert "rate limit" in r2.message.lower() or r2.metadata.get("rate_limited", False) is True

    def test_anomaly_detection_quarantine(self, guardrail, basic_agent_identity, runtime_context):
        """Force anomaly detection to trigger quarantine by lowering threshold"""
        # Lower threshold so any marginal risk causes quarantine
        guardrail.anomaly_threshold = 0.0

        token = guardrail.generate_capability_token(
            agent_id=basic_agent_identity.agent_id,
            tool_name="test.read",
            allowed_actions=[ToolAction.READ],
            constraints={},
            validity_hours=1,
            session_id=runtime_context.session_id
        )

        # Add suspicious argument to increase risk
        result = guardrail.check_tool_call("test.read", {"query": "SELECT * FROM users; DROP TABLE secrets;"}, context={
            "agent_identity": basic_agent_identity,
            "capability_token": token,
            "runtime_context": runtime_context
        })

        assert result.action == GuardrailAction.BLOCK
        assert result.severity == GuardrailSeverity.CRITICAL or "anomalous" in result.message.lower()

    def test_get_policy_summary_and_generate_token(self, guardrail, basic_agent_identity):
        """Test policy summary integrity and capability token generation"""
        token = guardrail.generate_capability_token(
            agent_id=basic_agent_identity.agent_id,
            tool_name="test.read",
            allowed_actions=[ToolAction.READ],
            constraints={"max_rows": 10},
            validity_hours=2,
            session_id="sess123"
        )

        # signature should verify
        assert token.verify_signature(guardrail.signing_key) is True

        summary = guardrail.get_policy_summary()
        assert isinstance(summary, dict)
        assert summary["guardrail_name"] == guardrail.name
        assert "registered_tools" in summary
        assert "test.read" in summary["tools"]

    def test_has_suspicious_args_private_method(self, guardrail):
        """Test that suspicious args detection flags malicious patterns"""
        benign = {"query": "select name from users where id = 1"}
        malicious = {"payload": "<script>alert('x')</script>"}

        assert guardrail._has_suspicious_args(benign) is False
        assert guardrail._has_suspicious_args(malicious) is True

    def test_calculate_risk_score_behavior(self, guardrail, basic_agent_identity, runtime_context):
        """Calculate risk score is bounded and responsive to recent calls"""
        # Baseline
        score1 = guardrail._calculate_risk_score(basic_agent_identity, "test.read", {}, runtime_context)
        assert 0.0 <= score1 <= 1.0

        # Simulate many recent calls to increase risk
        runtime_context.recent_tool_calls = ["test.read"] * 20 + ["other"] * 5
        score2 = guardrail._calculate_risk_score(basic_agent_identity, "test.read", {}, runtime_context)
        assert score2 >= score1

    def test_generate_token_allows_actions_constraints(self, guardrail, basic_agent_identity):
        """Generated capability token respects allowed actions and constraints"""
        token = guardrail.generate_capability_token(
            agent_id=basic_agent_identity.agent_id,
            tool_name="test.read",
            allowed_actions=[ToolAction.READ, ToolAction.INVOKE],
            constraints={"max_rows": 5},
            validity_hours=1
        )

        assert token.allows_action(ToolAction.READ)
        assert token.allows_action(ToolAction.INVOKE)
        assert not token.allows_action(ToolAction.WRITE)

        passed, err = token.check_constraints({"limit": 3})
        assert passed is True
        passed, err = token.check_constraints({"limit": 10})
        assert passed is False

    def test_development_guardrail_creation(self):
        """Create development guardrail and verify permissive settings"""
        dev = create_development_tool_access_guardrail()
        summary = dev.get_policy_summary()
        assert "DevelopmentToolAccessControl" in summary["guardrail_name"] or dev.name == "DevelopmentToolAccessControl"
        # In development guardrail, anomaly detection should be disabled by default
        assert dev.enable_anomaly_detection is False or summary["configuration"]["anomaly_detection_enabled"] is False

    def test_production_guardrail_creation(self):
        """Create production guardrail and verify registered tools"""
        prod = create_production_tool_access_guardrail()
        summary = prod.get_policy_summary()
        assert "finance.transfer" in summary["tools"]
        assert "vault.get_secret" in summary["tools"]
