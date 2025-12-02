# agnoguard/guardrails/input_validation.py
import re
from typing import Dict, Any, Optional, List
from ..core.base import InputGuardrail, GuardrailResult, GuardrailAction, GuardrailSeverity


class PIIDetectionGuardrailExtended(InputGuardrail):
    """Detects and redacts PII including SSN, credit cards, emails, phone numbers"""
    
    def __init__(self, redact: bool = True, **kwargs):
        super().__init__(**kwargs)
        self.redact = redact
        self.patterns = {
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b',
            'ip_address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        }
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        found_pii = {}
        modified_content = content
        
        for pii_type, pattern in self.patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                found_pii[pii_type] = len(matches)
                if self.redact:
                    modified_content = re.sub(pattern, f'[REDACTED_{pii_type.upper()}]', modified_content)
        
        if found_pii:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.REDACT if self.redact else GuardrailAction.BLOCK,
                severity=GuardrailSeverity.ERROR,
                message=f"PII detected: {', '.join(found_pii.keys())}",
                metadata={"found_pii": found_pii},
                modified_content=modified_content if self.redact else None
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="No PII detected",
            metadata={}
        )


class PHIAwarenessGuardrail(InputGuardrail):
    """Detects Protected Health Information (PHI)"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.medical_keywords = [
            'diagnosis', 'patient', 'medical record', 'prescription', 
            'treatment', 'disease', 'medication', 'blood pressure',
            'heart rate', 'lab results', 'x-ray', 'mri', 'ct scan'
        ]
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        content_lower = content.lower()
        found_terms = [term for term in self.medical_keywords if term in content_lower]
        
        # Simple heuristic: if multiple medical terms + potential identifiers
        has_potential_phi = len(found_terms) >= 2
        
        if has_potential_phi:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.BLOCK,
                severity=GuardrailSeverity.CRITICAL,
                message="Potential PHI detected",
                metadata={"medical_terms": found_terms}
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="No PHI detected",
            metadata={}
        )


class URLAndFileBlockerGuardrail(InputGuardrail):
    """Blocks or flags URLs and file paths in input"""
    
    def __init__(self, block_urls: bool = True, block_paths: bool = True, **kwargs):
        super().__init__(**kwargs)
        self.block_urls = block_urls
        self.block_paths = block_paths
        self.url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        self.file_pattern = r'(?:[a-zA-Z]:\\|/|~/)[^\s<>"{}|\\^`\[\]]*'
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        issues = []
        
        if self.block_urls:
            urls = re.findall(self.url_pattern, content)
            if urls:
                issues.append(f"{len(urls)} URL(s)")
        
        if self.block_paths:
            paths = re.findall(self.file_pattern, content)
            if paths:
                issues.append(f"{len(paths)} file path(s)")
        
        if issues:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.BLOCK,
                severity=GuardrailSeverity.WARNING,
                message=f"Found {', '.join(issues)}",
                metadata={"issues": issues}
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="No URLs or file paths detected",
            metadata={}
        )


class SecretsInInputGuardrail(InputGuardrail):
    """Detects secrets like API keys, tokens, passwords"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.patterns = {
            'api_key': r'(?i)(api[_-]?key|apikey)[\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?',
            'bearer_token': r'(?i)bearer\s+([a-zA-Z0-9_\-\.]+)',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'github_token': r'ghp_[a-zA-Z0-9]{36}',
            'slack_token': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
            'private_key': r'-----BEGIN (?:RSA |DSA )?PRIVATE KEY-----'
        }
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        found_secrets = {}
        
        for secret_type, pattern in self.patterns.items():
            if re.search(pattern, content):
                found_secrets[secret_type] = True
        
        if found_secrets:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.BLOCK,
                severity=GuardrailSeverity.CRITICAL,
                message=f"Secrets detected: {', '.join(found_secrets.keys())}",
                metadata={"found_secrets": list(found_secrets.keys())}
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="No secrets detected",
            metadata={}
        )


class InputSizeGuardrail(InputGuardrail):
    """Limits input size to prevent abuse"""
    
    def __init__(self, max_chars: int = 50000, max_tokens: Optional[int] = None, **kwargs):
        super().__init__(**kwargs)
        self.max_chars = max_chars
        self.max_tokens = max_tokens
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        char_count = len(content)
        
        if char_count > self.max_chars:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.BLOCK,
                severity=GuardrailSeverity.ERROR,
                message=f"Input exceeds {self.max_chars} characters ({char_count})",
                metadata={"char_count": char_count, "max_chars": self.max_chars}
            )
        
        # Simple token estimation (rough)
        if self.max_tokens:
            estimated_tokens = len(content.split())
            if estimated_tokens > self.max_tokens:
                return GuardrailResult(
                    passed=False,
                    action=GuardrailAction.BLOCK,
                    severity=GuardrailSeverity.ERROR,
                    message=f"Input exceeds {self.max_tokens} tokens (est. {estimated_tokens})",
                    metadata={"estimated_tokens": estimated_tokens, "max_tokens": self.max_tokens}
                )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="Input size within limits",
            metadata={"char_count": char_count}
        )


class DangerousPatternsGuardrail(InputGuardrail):
    """Detects dangerous patterns like SQL injection, command injection"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.patterns = {
            'sql_injection': r'(?i)(union.*select|drop\s+table|delete\s+from|insert\s+into)',
            'command_injection': r'[;&|`$(){}]',
            'path_traversal': r'\.\./|\.\.',
            'xss': r'<script|javascript:|onerror=|onload='
        }
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        found_patterns = []
        
        for pattern_name, pattern in self.patterns.items():
            if re.search(pattern, content):
                found_patterns.append(pattern_name)
        
        if found_patterns:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.BLOCK,
                severity=GuardrailSeverity.CRITICAL,
                message=f"Dangerous patterns detected: {', '.join(found_patterns)}",
                metadata={"patterns": found_patterns}
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="No dangerous patterns detected",
            metadata={}
        )


class RegexFilterGuardrail(InputGuardrail):
    """User-configurable regex filter"""
    
    def __init__(self, patterns: List[Dict[str, Any]], **kwargs):
        super().__init__(**kwargs)
        self.patterns = patterns
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        violations = []
        
        for pattern_config in self.patterns:
            pattern = pattern_config['pattern']
            name = pattern_config.get('name', pattern)
            action = pattern_config.get('action', 'block')
            
            if re.search(pattern, content):
                violations.append(name)
        
        if violations:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.BLOCK,
                severity=GuardrailSeverity.WARNING,
                message=f"Matched patterns: {', '.join(violations)}",
                metadata={"matched_patterns": violations}
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="No pattern matches",
            metadata={}
        )


class LanguageRestrictionGuardrail(InputGuardrail):
    """Restricts input to certain languages"""
    
    def __init__(self, allowed_languages: List[str] = ['en'], **kwargs):
        super().__init__(**kwargs)
        self.allowed_languages = allowed_languages
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        # Simple heuristic: check for non-ASCII characters
        has_non_ascii = any(ord(char) > 127 for char in content)
        
        if 'en' in self.allowed_languages and has_non_ascii:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.WARN,
                severity=GuardrailSeverity.WARNING,
                message="Non-English characters detected",
                metadata={"has_non_ascii": has_non_ascii}
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="Language check passed",
            metadata={}
        )