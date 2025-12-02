# ==========================================
# agnoguard/guardrails/privacy.py
# Privacy & Compliance Guardrails
# ==========================================

import re
from typing import Dict, Any, Optional, List
from ..core.base import InputGuardrail, GuardrailResult, GuardrailAction, GuardrailSeverity


class GDPRDataMinimizationGuardrail(InputGuardrail):
    """Ensures data minimization principles (GDPR Article 5)"""
    
    def __init__(self, max_personal_fields: int = 5, **kwargs):
        super().__init__(**kwargs)
        self.max_personal_fields = max_personal_fields
        self.personal_data_indicators = [
            'name', 'email', 'phone', 'address', 'age', 'birthday',
            'ssn', 'passport', 'license', 'credit card'
        ]
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        content_lower = content.lower()
        found_fields = [ind for ind in self.personal_data_indicators if ind in content_lower]
        
        if len(found_fields) > self.max_personal_fields:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.WARN,
                severity=GuardrailSeverity.WARNING,
                message=f"Excessive personal data fields ({len(found_fields)}). GDPR minimization principle.",
                metadata={"fields_count": len(found_fields), "max": self.max_personal_fields}
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="Data minimization OK",
            metadata={"fields_count": len(found_fields)}
        )


class UserConsentValidationGuardrail(InputGuardrail):
    """Validates user consent before processing personal data"""
    
    def __init__(self, require_consent: bool = True, **kwargs):
        super().__init__(**kwargs)
        self.require_consent = require_consent
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        if not self.require_consent:
            return GuardrailResult(
                passed=True,
                action=GuardrailAction.ALLOW,
                severity=GuardrailSeverity.INFO,
                message="Consent not required",
                metadata={}
            )
        
        # Check context for consent flag
        has_consent = context and context.get('user_consent', False)
        
        # Check if content contains personal data indicators
        has_personal_data = any(term in content.lower() for term in 
                               ['email', 'phone', 'address', 'name'])
        
        if has_personal_data and not has_consent:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.BLOCK,
                severity=GuardrailSeverity.ERROR,
                message="Personal data processing requires user consent",
                metadata={"has_consent": has_consent, "has_personal_data": has_personal_data}
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="Consent validation passed",
            metadata={"has_consent": has_consent}
        )


class RetentionCheckGuardrail(InputGuardrail):
    """Checks data retention compliance"""
    
    def __init__(self, max_retention_days: int = 90, **kwargs):
        super().__init__(**kwargs)
        self.max_retention_days = max_retention_days
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        if not context or 'data_age_days' not in context:
            return GuardrailResult(
                passed=True,
                action=GuardrailAction.ALLOW,
                severity=GuardrailSeverity.INFO,
                message="No retention data available",
                metadata={}
            )
        
        data_age = context.get('data_age_days', 0)
        
        if data_age > self.max_retention_days:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.BLOCK,
                severity=GuardrailSeverity.ERROR,
                message=f"Data exceeds retention period ({data_age} > {self.max_retention_days} days)",
                metadata={"data_age_days": data_age, "max_days": self.max_retention_days}
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="Retention period valid",
            metadata={"data_age_days": data_age}
        )


class RightToErasureRequestDetector(InputGuardrail):
    """Detects GDPR right to erasure (right to be forgotten) requests"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.erasure_patterns = [
            r'(?i)delete\s+(my|all)\s+(data|information|account)',
            r'(?i)remove\s+(my|all)\s+(data|information)',
            r'(?i)right\s+to\s+(be\s+)?forgotten',
            r'(?i)erase\s+(my|all)\s+(data|information)',
            r'(?i)gdpr\s+(deletion|erasure)\s+request',
        ]
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        for pattern in self.erasure_patterns:
            if re.search(pattern, content):
                return GuardrailResult(
                    passed=False,
                    action=GuardrailAction.WARN,
                    severity=GuardrailSeverity.WARNING,
                    message="GDPR right to erasure request detected - escalate to compliance team",
                    metadata={"pattern": pattern, "requires_action": True}
                )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="No erasure request detected",
            metadata={}
        )

