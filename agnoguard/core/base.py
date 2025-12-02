# agnoguard/core/base.py
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, List
from enum import Enum
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


class GuardrailSeverity(Enum):
    """Severity levels for guardrail violations"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class GuardrailAction(Enum):
    """Actions to take when guardrail is triggered"""
    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"
    WARN = "warn"
    MODIFY = "modify"


@dataclass
class GuardrailResult:
    """Result of a guardrail check"""
    passed: bool
    action: GuardrailAction
    severity: GuardrailSeverity
    message: str
    metadata: Dict[str, Any]
    modified_content: Optional[str] = None
    
    def __bool__(self):
        return self.passed


class BaseGuardrail(ABC):
    """Base class for all guardrails"""
    
    def __init__(
        self,
        name: Optional[str] = None,
        enabled: bool = True,
        severity: GuardrailSeverity = GuardrailSeverity.ERROR,
        action: GuardrailAction = GuardrailAction.BLOCK,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.name = name or self.__class__.__name__
        self.enabled = enabled
        self.severity = severity
        self.action = action
        self.metadata = metadata or {}
        
    @abstractmethod
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        """
        Check if content passes the guardrail
        
        Args:
            content: The content to check
            context: Additional context (user info, session data, etc.)
            
        Returns:
            GuardrailResult with check outcome
        """
        pass
    
    def __call__(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        """Make guardrail callable"""
        if not self.enabled:
            return GuardrailResult(
                passed=True,
                action=GuardrailAction.ALLOW,
                severity=GuardrailSeverity.INFO,
                message=f"{self.name} is disabled",
                metadata={"guardrail": self.name, "enabled": False}
            )
        
        try:
            result = self.check(content, context)
            logger.info(f"{self.name}: {'PASSED' if result.passed else 'FAILED'} - {result.message}")
            return result
        except Exception as e:
            logger.error(f"{self.name} error: {str(e)}", exc_info=True)
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.BLOCK,
                severity=GuardrailSeverity.CRITICAL,
                message=f"Guardrail error: {str(e)}",
                metadata={"error": str(e), "guardrail": self.name}
            )


class InputGuardrail(BaseGuardrail):
    """Base class for input validation guardrails"""
    pass


class OutputGuardrail(BaseGuardrail):
    """Base class for output validation guardrails"""
    pass


class ToolGuardrail(BaseGuardrail):
    """Base class for tool/capability guardrails"""
    
    @abstractmethod
    def check_tool_call(self, tool_name: str, tool_args: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        """Check if a tool call is allowed"""
        pass