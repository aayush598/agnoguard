
# ==========================================
# agnoguard/guardrails/operational.py
# Operational Guardrails
# ==========================================

from ..core.base import InputGuardrail, OutputGuardrail, GuardrailResult, GuardrailAction, GuardrailSeverity


class ModelVersionPinGuardrail(InputGuardrail):
    """Ensures specific model version is used"""
    
    def __init__(self, required_version: str = None, **kwargs):
        super().__init__(**kwargs)
        self.required_version = required_version
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        if not self.required_version:
            return GuardrailResult(
                passed=True,
                action=GuardrailAction.ALLOW,
                severity=GuardrailSeverity.INFO,
                message="No version requirement",
                metadata={}
            )
        
        model_version = context.get('model_version') if context else None
        
        if model_version != self.required_version:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.WARN,
                severity=GuardrailSeverity.WARNING,
                message=f"Model version mismatch: {model_version} != {self.required_version}",
                metadata={"current": model_version, "required": self.required_version}
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="Model version OK",
            metadata={"version": model_version}
        )


class TelemetryEnforcementGuardrail(InputGuardrail):
    """Ensures telemetry is being collected"""
    
    def __init__(self, require_telemetry: bool = True, **kwargs):
        super().__init__(**kwargs)
        self.require_telemetry = require_telemetry
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        if not self.require_telemetry:
            return GuardrailResult(
                passed=True,
                action=GuardrailAction.ALLOW,
                severity=GuardrailSeverity.INFO,
                message="Telemetry not required",
                metadata={}
            )
        
        has_telemetry = context and context.get('telemetry_enabled', False)
        
        if not has_telemetry:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.WARN,
                severity=GuardrailSeverity.WARNING,
                message="Telemetry not enabled",
                metadata={"telemetry_enabled": False}
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="Telemetry enabled",
            metadata={"telemetry_enabled": True}
        )


class QualityThresholdGuardrail(OutputGuardrail):
    """Checks output quality metrics"""
    
    def __init__(self, min_confidence: float = 0.7, min_length: int = 10, **kwargs):
        super().__init__(**kwargs)
        self.min_confidence = min_confidence
        self.min_length = min_length
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        # Check length
        if len(content) < self.min_length:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.WARN,
                severity=GuardrailSeverity.WARNING,
                message=f"Output too short: {len(content)} < {self.min_length}",
                metadata={"length": len(content), "min_length": self.min_length}
            )
        
        # Check confidence if available
        if context and 'confidence' in context:
            confidence = context['confidence']
            if confidence < self.min_confidence:
                return GuardrailResult(
                    passed=False,
                    action=GuardrailAction.WARN,
                    severity=GuardrailSeverity.WARNING,
                    message=f"Low confidence: {confidence} < {self.min_confidence}",
                    metadata={"confidence": confidence, "threshold": self.min_confidence}
                )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="Quality check passed",
            metadata={"length": len(content)}
        )


class APIRateLimitGuardrail(InputGuardrail):
    """Rate limits API calls per user/key"""
    
    def __init__(self, calls_per_minute: int = 60, **kwargs):
        super().__init__(**kwargs)
        self.calls_per_minute = calls_per_minute
        self.call_history = {}
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        import time
        
        api_key = context.get('api_key', 'default') if context else 'default'
        current_time = time.time()
        
        if api_key not in self.call_history:
            self.call_history[api_key] = []
        
        # Clean old calls (older than 1 minute)
        self.call_history[api_key] = [
            t for t in self.call_history[api_key]
            if current_time - t < 60
        ]
        
        # Check rate limit
        if len(self.call_history[api_key]) >= self.calls_per_minute:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.BLOCK,
                severity=GuardrailSeverity.ERROR,
                message=f"API rate limit exceeded: {self.calls_per_minute}/min",
                metadata={
                    "calls": len(self.call_history[api_key]),
                    "limit": self.calls_per_minute
                }
            )
        
        # Add current call
        self.call_history[api_key].append(current_time)
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="Rate limit OK",
            metadata={
                "calls": len(self.call_history[api_key]),
                "limit": self.calls_per_minute
            }
        )


class FileWriteRestrictionGuardrail(InputGuardrail):
    """Restricts file write operations"""
    
    def __init__(self, allowed_paths: Optional[List[str]] = None, **kwargs):
        super().__init__(**kwargs)
        self.allowed_paths = allowed_paths or ['/tmp', '/var/tmp']
        self.file_write_patterns = [
            r'(?i)(write|save|create)\s+(file|document)',
            r'(?i)file\.(write|save)',
            r'(?i)open\s*\([\'"][^\'"]+(w|a)',
        ]
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        # Check if content mentions file writing
        has_file_write = any(re.search(pattern, content) for pattern in self.file_write_patterns)
        
        if has_file_write:
            # Check if path is allowed
            is_allowed = any(allowed in content for allowed in self.allowed_paths)
            
            if not is_allowed:
                return GuardrailResult(
                    passed=False,
                    action=GuardrailAction.BLOCK,
                    severity=GuardrailSeverity.CRITICAL,
                    message="File write to restricted location",
                    metadata={"allowed_paths": self.allowed_paths}
                )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="File write check passed",
            metadata={}
        )


# ==========================================
# Additional Security Guardrails
# ==========================================

class EnvironmentVariableLeakGuardrail(OutputGuardrail):
    """Prevents environment variable leakage"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.env_patterns = [
            r'(?i)(api[_-]?key|secret|password|token)[\s:=]+[a-zA-Z0-9_\-]{10,}',
            r'(?i)export\s+\w+=[^\s]+',
            r'\$\w+',  # $VAR_NAME
        ]
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        for pattern in self.env_patterns:
            if re.search(pattern, content):
                return GuardrailResult(
                    passed=False,
                    action=GuardrailAction.BLOCK,
                    severity=GuardrailSeverity.CRITICAL,
                    message="Environment variable leak detected",
                    metadata={"pattern": pattern}
                )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="No env var leaks",
            metadata={}
        )