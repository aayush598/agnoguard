# agnoguard/guardrails/output_validation.py
import re
import json
from typing import Dict, Any, Optional, List
from ..core.base import OutputGuardrail, GuardrailResult, GuardrailAction, GuardrailSeverity


class OutputPIIRedactionGuardrail(OutputGuardrail):
    """Redacts PII from model outputs"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.patterns = {
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b',
        }
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        found_pii = {}
        modified_content = content
        
        for pii_type, pattern in self.patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                found_pii[pii_type] = len(matches)
                modified_content = re.sub(pattern, f'[REDACTED]', modified_content)
        
        if found_pii:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.REDACT,
                severity=GuardrailSeverity.WARNING,
                message=f"PII redacted from output: {', '.join(found_pii.keys())}",
                metadata={"redacted_pii": found_pii},
                modified_content=modified_content
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="No PII in output",
            metadata={}
        )


class SecretLeakOutputGuardrail(OutputGuardrail):
    """Prevents secrets from appearing in outputs"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.secret_patterns = {
            'api_key': r'(?i)(api[_-]?key|apikey)[\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?',
            'password': r'(?i)(password|passwd|pwd)[\s:=]+["\']?([^\s"\']{8,})["\']?',
            'token': r'(?i)(token|jwt)[\s:=]+["\']?([a-zA-Z0-9_\-\.]{20,})["\']?',
        }
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        found_secrets = []
        modified_content = content
        
        for secret_type, pattern in self.secret_patterns.items():
            if re.search(pattern, content):
                found_secrets.append(secret_type)
                modified_content = re.sub(pattern, r'\1=[REDACTED]', modified_content)
        
        if found_secrets:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.REDACT,
                severity=GuardrailSeverity.CRITICAL,
                message=f"Secrets found in output: {', '.join(found_secrets)}",
                metadata={"found_secrets": found_secrets},
                modified_content=modified_content
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="No secrets in output",
            metadata={}
        )


class InternalDataLeakGuardrail(OutputGuardrail):
    """Detects internal data patterns in output"""
    
    def __init__(self, internal_domains: Optional[List[str]] = None, **kwargs):
        super().__init__(**kwargs)
        self.internal_domains = internal_domains or ['internal', 'corp', 'intranet']
        self.internal_patterns = [
            r'(?i)internal\s+(server|database|api)',
            r'(?i)localhost:\d+',
            r'127\.0\.0\.1',
            r'192\.168\.\d+\.\d+',
            r'10\.\d+\.\d+\.\d+',
        ]
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        violations = []
        
        # Check internal domains
        for domain in self.internal_domains:
            if domain in content.lower():
                violations.append(f"internal_domain:{domain}")
        
        # Check internal patterns
        for pattern in self.internal_patterns:
            if re.search(pattern, content):
                violations.append("internal_infrastructure")
                break
        
        if violations:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.BLOCK,
                severity=GuardrailSeverity.CRITICAL,
                message="Internal data detected in output",
                metadata={"violations": violations}
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="No internal data leakage",
            metadata={}
        )


class ConfidentialityGuardrail(OutputGuardrail):
    """Detects confidential markers in output"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.confidential_markers = [
            'confidential', 'proprietary', 'classified',
            'secret', 'internal only', 'not for distribution'
        ]
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        content_lower = content.lower()
        found_markers = [m for m in self.confidential_markers if m in content_lower]
        
        if found_markers:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.BLOCK,
                severity=GuardrailSeverity.CRITICAL,
                message=f"Confidential markers found: {', '.join(found_markers)}",
                metadata={"markers": found_markers}
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="No confidentiality issues",
            metadata={}
        )


class OutputSchemaValidationGuardrail(OutputGuardrail):
    """Validates output against expected schema"""
    
    def __init__(self, expected_schema: Optional[Dict[str, Any]] = None, **kwargs):
        super().__init__(**kwargs)
        self.expected_schema = expected_schema
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        if not self.expected_schema:
            return GuardrailResult(
                passed=True,
                action=GuardrailAction.ALLOW,
                severity=GuardrailSeverity.INFO,
                message="No schema validation configured",
                metadata={}
            )
        
        try:
            # Try to parse as JSON
            data = json.loads(content)
            
            # Basic schema validation (can be extended)
            required_fields = self.expected_schema.get('required', [])
            missing_fields = [f for f in required_fields if f not in data]
            
            if missing_fields:
                return GuardrailResult(
                    passed=False,
                    action=GuardrailAction.BLOCK,
                    severity=GuardrailSeverity.ERROR,
                    message=f"Missing required fields: {', '.join(missing_fields)}",
                    metadata={"missing_fields": missing_fields}
                )
            
            return GuardrailResult(
                passed=True,
                action=GuardrailAction.ALLOW,
                severity=GuardrailSeverity.INFO,
                message="Schema validation passed",
                metadata={}
            )
            
        except json.JSONDecodeError:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.WARN,
                severity=GuardrailSeverity.WARNING,
                message="Output is not valid JSON",
                metadata={"error": "invalid_json"}
            )


class HallucinationRiskGuardrail(OutputGuardrail):
    """Detects high confidence claims that may be hallucinations"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.high_confidence_patterns = [
            r'(?i)(definitely|certainly|absolutely|guaranteed)',
            r'(?i)(always|never|impossible|100%)',
            r'(?i)(proven fact|scientific fact|undeniable)',
        ]
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        high_confidence_count = sum(
            1 for pattern in self.high_confidence_patterns 
            if re.search(pattern, content)
        )
        
        if high_confidence_count >= 3:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.WARN,
                severity=GuardrailSeverity.WARNING,
                message="High confidence claims detected - potential hallucination risk",
                metadata={"high_confidence_count": high_confidence_count}
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="No hallucination risk detected",
            metadata={}
        )


class CitationRequiredGuardrail(OutputGuardrail):
    """Ensures factual claims have citations"""
    
    def __init__(self, require_citations: bool = True, **kwargs):
        super().__init__(**kwargs)
        self.require_citations = require_citations
        self.citation_patterns = [
            r'\[\d+\]',  # [1], [2]
            r'\(Source:',  # (Source: ...)
            r'According to',
            r'https?://',  # URLs
        ]
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        if not self.require_citations:
            return GuardrailResult(
                passed=True,
                action=GuardrailAction.ALLOW,
                severity=GuardrailSeverity.INFO,
                message="Citations not required",
                metadata={}
            )
        
        has_citations = any(re.search(pattern, content) for pattern in self.citation_patterns)
        
        # Simple heuristic: long factual-looking content should have citations
        is_long = len(content) > 500
        looks_factual = any(word in content.lower() for word in ['research', 'study', 'shows', 'data', 'statistics'])
        
        if is_long and looks_factual and not has_citations:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.WARN,
                severity=GuardrailSeverity.WARNING,
                message="Factual claims without citations",
                metadata={"has_citations": False}
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="Citation check passed",
            metadata={"has_citations": has_citations}
        )


class CommandInjectionOutputGuardrail(OutputGuardrail):
    """Prevents command injection in output that might be executed"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.dangerous_commands = [
            'rm -rf', 'sudo', 'chmod', 'eval', 'exec',
            'DROP TABLE', 'DELETE FROM', '; --', '| bash'
        ]
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        found_commands = [cmd for cmd in self.dangerous_commands if cmd in content]
        
        if found_commands:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.BLOCK,
                severity=GuardrailSeverity.CRITICAL,
                message=f"Dangerous commands in output: {', '.join(found_commands)}",
                metadata={"dangerous_commands": found_commands}
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="No command injection detected",
            metadata={}
        )