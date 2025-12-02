# agnoguard/__init__.py
"""
AgnoGuard - Comprehensive LLM Guardrails for Agno Framework

A production-ready library providing 50+ guardrails for:
- Input validation and security
- Prompt injection & jailbreak detection  
- Output validation & leakage prevention
- Content safety
- Tool & capability control
- Privacy & compliance
- Operational monitoring
"""

__version__ = "0.1.0"
__author__ = "Your Name"

from .suite import GuardrailSuite, GuardrailViolationError
from .policy import apply_policy, PolicyBuilder, apply_policy_suite
from .profiles import list_profiles, get_profile
from .core.base import (
    BaseGuardrail,
    InputGuardrail, 
    OutputGuardrail,
    ToolGuardrail,
    GuardrailResult,
    GuardrailAction,
    GuardrailSeverity
)

# Import all guardrail classes for easy access
from .guardrails.input_validation import (
    PIIDetectionGuardrailExtended,
    PHIAwarenessGuardrail,
    URLAndFileBlockerGuardrail,
    SecretsInInputGuardrail,
    InputSizeGuardrail,
    DangerousPatternsGuardrail,
    RegexFilterGuardrail,
    LanguageRestrictionGuardrail,
)

from .guardrails.injection import (
    PromptInjectionSignatureGuardrail,
    SystemPromptLeakGuardrail,
    JailbreakPatternGuardrail,
    RolePlayInjectionGuardrail,
    OverrideInstructionGuardrail,
    CrossContextManipulationGuardrail,
    LLMClassifierInjectionGuardrail,
)

from .guardrails.output_validation import (
    OutputPIIRedactionGuardrail,
    SecretLeakOutputGuardrail,
    InternalDataLeakGuardrail,
    ConfidentialityGuardrail,
    OutputSchemaValidationGuardrail,
    HallucinationRiskGuardrail,
    CitationRequiredGuardrail,
    CommandInjectionOutputGuardrail,
)

from .guardrails.content_safety import (
    NSFWContentGuardrail,
    HateSpeechGuardrail,
    ViolenceGuardrail,
    SelfHarmGuardrail,
    MedicalAdviceGuardrail,
    ToolAccessControlGuardrail,
    DestructiveToolCallGuardrail,
    RateLimitGuardrail,
    CostThresholdGuardrail,
)

__all__ = [
    # Core
    "GuardrailSuite",
    "GuardrailViolationError",
    "apply_policy",
    "PolicyBuilder",
    "list_profiles",
    
    # Base classes
    "BaseGuardrail",
    "InputGuardrail",
    "OutputGuardrail",
    "ToolGuardrail",
    "GuardrailResult",
    "GuardrailAction",
    "GuardrailSeverity",
    
    # Input guardrails
    "PIIDetectionGuardrailExtended",
    "PHIAwarenessGuardrail",
    "URLAndFileBlockerGuardrail",
    "SecretsInInputGuardrail",
    "InputSizeGuardrail",
    "DangerousPatternsGuardrail",
    "RegexFilterGuardrail",
    "LanguageRestrictionGuardrail",
    
    # Injection guardrails
    "PromptInjectionSignatureGuardrail",
    "SystemPromptLeakGuardrail",
    "JailbreakPatternGuardrail",
    "RolePlayInjectionGuardrail",
    "OverrideInstructionGuardrail",
    "CrossContextManipulationGuardrail",
    "LLMClassifierInjectionGuardrail",
    
    # Output guardrails
    "OutputPIIRedactionGuardrail",
    "SecretLeakOutputGuardrail",
    "InternalDataLeakGuardrail",
    "ConfidentialityGuardrail",
    "OutputSchemaValidationGuardrail",
    "HallucinationRiskGuardrail",
    "CitationRequiredGuardrail",
    "CommandInjectionOutputGuardrail",
    
    # Content safety & tools
    "NSFWContentGuardrail",
    "HateSpeechGuardrail",
    "ViolenceGuardrail",
    "SelfHarmGuardrail",
    "MedicalAdviceGuardrail",
    "ToolAccessControlGuardrail",
    "DestructiveToolCallGuardrail",
    "RateLimitGuardrail",
    "CostThresholdGuardrail",
]