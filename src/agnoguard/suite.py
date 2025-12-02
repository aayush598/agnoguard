# agnoguard/suite.py
from typing import List, Dict, Any, Optional, Callable
from .core.base import BaseGuardrail, GuardrailResult, GuardrailAction
from .profiles import BUILTIN_PROFILES
import logging

logger = logging.getLogger(__name__)


class GuardrailSuite:
    """Main suite that manages multiple guardrails"""
    
    def __init__(self, profile: str = "default", custom_guardrails: Optional[List[BaseGuardrail]] = None):
        """
        Initialize GuardrailSuite
        
        Args:
            profile: Name of the profile to load (default, enterprise_security, child_safety, etc.)
            custom_guardrails: Additional guardrails to add
        """
        self.profile = profile
        self.input_guardrails: List[BaseGuardrail] = []
        self.output_guardrails: List[BaseGuardrail] = []
        self.tool_guardrails: List[BaseGuardrail] = []
        
        # Load profile
        self._load_profile(profile)
        
        # Add custom guardrails
        if custom_guardrails:
            for gr in custom_guardrails:
                self.add_guardrail(gr)
    
    @classmethod
    def load_profile(cls, profile_name: str) -> 'GuardrailSuite':
        """Load a predefined profile"""
        return cls(profile=profile_name)
    
    def _load_profile(self, profile_name: str):
        """Load guardrails from a profile"""
        if profile_name not in BUILTIN_PROFILES:
            logger.warning(f"Profile '{profile_name}' not found, using default")
            profile_name = "default"
        
        profile_config = BUILTIN_PROFILES[profile_name]
        
        # Instantiate guardrails from config
        from . import guardrails as gr_module
        
        for gr_config in profile_config.get("input_guardrails", []):
            gr_class = getattr(gr_module, gr_config["class"])
            instance = gr_class(**gr_config.get("config", {}))
            self.input_guardrails.append(instance)
        
        for gr_config in profile_config.get("output_guardrails", []):
            gr_class = getattr(gr_module, gr_config["class"])
            instance = gr_class(**gr_config.get("config", {}))
            self.output_guardrails.append(instance)
        
        for gr_config in profile_config.get("tool_guardrails", []):
            gr_class = getattr(gr_module, gr_config["class"])
            instance = gr_class(**gr_config.get("config", {}))
            self.tool_guardrails.append(instance)
    
    def add_guardrail(self, guardrail: BaseGuardrail, category: str = "input"):
        """Add a guardrail to the suite"""
        from .core.base import InputGuardrail, OutputGuardrail, ToolGuardrail
        
        if isinstance(guardrail, InputGuardrail) or category == "input":
            self.input_guardrails.append(guardrail)
        elif isinstance(guardrail, OutputGuardrail) or category == "output":
            self.output_guardrails.append(guardrail)
        elif isinstance(guardrail, ToolGuardrail) or category == "tool":
            self.tool_guardrails.append(guardrail)
        else:
            self.input_guardrails.append(guardrail)
    
    def check_input(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        """Check content against all input guardrails"""
        return self._check_guardrails(self.input_guardrails, content, context)
    
    def check_output(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        """Check content against all output guardrails"""
        return self._check_guardrails(self.output_guardrails, content, context)
    
    def _check_guardrails(self, guardrails: List[BaseGuardrail], content: str, context: Optional[Dict[str, Any]]) -> GuardrailResult:
        """Run content through multiple guardrails"""
        modified_content = content
        all_metadata = {}
        failed_guardrails = []
        
        for guardrail in guardrails:
            result = guardrail(modified_content, context)
            all_metadata[guardrail.name] = result.metadata
            
            if not result.passed:
                failed_guardrails.append({
                    "name": guardrail.name,
                    "severity": result.severity.value,
                    "message": result.message
                })
                
                if result.action == GuardrailAction.BLOCK:
                    return GuardrailResult(
                        passed=False,
                        action=GuardrailAction.BLOCK,
                        severity=result.severity,
                        message=f"Blocked by {guardrail.name}: {result.message}",
                        metadata={"failed_guardrails": failed_guardrails, "all_checks": all_metadata}
                    )
                elif result.action == GuardrailAction.REDACT and result.modified_content:
                    modified_content = result.modified_content
        
        return GuardrailResult(
            passed=len(failed_guardrails) == 0,
            action=GuardrailAction.ALLOW if len(failed_guardrails) == 0 else GuardrailAction.WARN,
            severity=failed_guardrails[0]["severity"] if failed_guardrails else "info",
            message="All guardrails passed" if not failed_guardrails else "Some warnings",
            metadata={"failed_guardrails": failed_guardrails, "all_checks": all_metadata},
            modified_content=modified_content if modified_content != content else None
        )
    
    @property
    def pre_hooks(self) -> List[Callable]:
        """Get pre-hooks for Agno Team integration"""
        return [self._create_pre_hook()]
    
    @property
    def post_hooks(self) -> List[Callable]:
        """Get post-hooks for Agno Team integration"""
        return [self._create_post_hook()]
    
    @property
    def inputs(self) -> List[Callable]:
        """Alias for pre_hooks"""
        return self.pre_hooks
    
    @property
    def outputs(self) -> List[Callable]:
        """Alias for post_hooks"""
        return self.post_hooks
    
    def _create_pre_hook(self) -> Callable:
        """Create a pre-hook function for input validation"""
        def pre_hook(content: Any, context: Optional[Dict[str, Any]] = None) -> Any:
            # Convert content to string if needed
            content_str = str(content) if not isinstance(content, str) else content
            
            result = self.check_input(content_str, context)
            
            if not result.passed and result.action == GuardrailAction.BLOCK:
                raise GuardrailViolationError(result.message, result)
            
            # Return modified content if available
            if result.modified_content:
                return result.modified_content
            
            return content
        
        return pre_hook
    
    def _create_post_hook(self) -> Callable:
        """Create a post-hook function for output validation"""
        def post_hook(content: Any, context: Optional[Dict[str, Any]] = None) -> Any:
            # Convert content to string if needed
            content_str = str(content) if not isinstance(content, str) else content
            
            result = self.check_output(content_str, context)
            
            if not result.passed and result.action == GuardrailAction.BLOCK:
                raise GuardrailViolationError(result.message, result)
            
            # Return modified content if available (e.g., redacted PII)
            if result.modified_content:
                return result.modified_content
            
            return content
        
        return post_hook


class GuardrailViolationError(Exception):
    """Exception raised when a guardrail blocks content"""
    
    def __init__(self, message: str, result: GuardrailResult):
        super().__init__(message)
        self.result = result