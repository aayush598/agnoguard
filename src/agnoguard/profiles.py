# agnoguard/profiles.py
"""
Predefined guardrail profiles for common use cases
"""

BUILTIN_PROFILES = {
    "default": {
        "description": "Basic security and safety guardrails",
        "input_guardrails": [
            {
                "class": "PIIDetectionGuardrailExtended",
                "config": {"redact": True, "severity": "warning"}
            },
            {
                "class": "SecretsInInputGuardrail",
                "config": {"severity": "critical"}
            },
            {
                "class": "InputSizeGuardrail",
                "config": {"max_chars": 50000}
            },
            {
                "class": "PromptInjectionSignatureGuardrail",
                "config": {"severity": "critical"}
            },
            {
                "class": "NSFWContentGuardrail",
                "config": {"severity": "critical"}
            },
        ],
        "output_guardrails": [
            {
                "class": "OutputPIIRedactionGuardrail",
                "config": {}
            },
            {
                "class": "SecretLeakOutputGuardrail",
                "config": {}
            },
        ],
        "tool_guardrails": []
    },
    
    "enterprise_security": {
        "description": "Enterprise-grade security with strict controls",
        "input_guardrails": [
            {
                "class": "PIIDetectionGuardrailExtended",
                "config": {"redact": True, "severity": "error"}
            },
            {
                "class": "PHIAwarenessGuardrail",
                "config": {"severity": "critical"}
            },
            {
                "class": "SecretsInInputGuardrail",
                "config": {"severity": "critical"}
            },
            {
                "class": "URLAndFileBlockerGuardrail",
                "config": {"block_urls": True, "block_paths": True}
            },
            {
                "class": "InputSizeGuardrail",
                "config": {"max_chars": 25000}
            },
            {
                "class": "DangerousPatternsGuardrail",
                "config": {"severity": "critical"}
            },
            {
                "class": "PromptInjectionSignatureGuardrail",
                "config": {"severity": "critical"}
            },
            {
                "class": "SystemPromptLeakGuardrail",
                "config": {"severity": "critical"}
            },
            {
                "class": "JailbreakPatternGuardrail",
                "config": {"severity": "critical"}
            },
            {
                "class": "RateLimitGuardrail",
                "config": {"max_requests": 50, "window_seconds": 60}
            },
        ],
        "output_guardrails": [
            {
                "class": "OutputPIIRedactionGuardrail",
                "config": {}
            },
            {
                "class": "SecretLeakOutputGuardrail",
                "config": {}
            },
            {
                "class": "InternalDataLeakGuardrail",
                "config": {"internal_domains": ["internal", "corp", "intranet"]}
            },
            {
                "class": "ConfidentialityGuardrail",
                "config": {}
            },
            {
                "class": "CommandInjectionOutputGuardrail",
                "config": {}
            },
        ],
        "tool_guardrails": [
            {
                "class": "DestructiveToolCallGuardrail",
                "config": {}
            },
        ]
    },
    
    "child_safety": {
        "description": "Maximum safety for children and educational contexts",
        "input_guardrails": [
            {
                "class": "NSFWContentGuardrail",
                "config": {"severity": "critical"}
            },
            {
                "class": "HateSpeechGuardrail",
                "config": {"severity": "critical"}
            },
            {
                "class": "ViolenceGuardrail",
                "config": {"severity": "critical"}
            },
            {
                "class": "SelfHarmGuardrail",
                "config": {"severity": "critical"}
            },
            {
                "class": "PIIDetectionGuardrailExtended",
                "config": {"redact": True, "severity": "critical"}
            },
            {
                "class": "URLAndFileBlockerGuardrail",
                "config": {"block_urls": True, "block_paths": True}
            },
            {
                "class": "PromptInjectionSignatureGuardrail",
                "config": {"severity": "critical"}
            },
            {
                "class": "JailbreakPatternGuardrail",
                "config": {"severity": "critical"}
            },
        ],
        "output_guardrails": [
            {
                "class": "OutputPIIRedactionGuardrail",
                "config": {}
            },
            {
                "class": "NSFWContentGuardrail",
                "config": {"severity": "critical"}
            },
        ],
        "tool_guardrails": [
            {
                "class": "ToolAccessControlGuardrail",
                "config": {"allowed_tools": ["search", "calculator"]}
            },
        ]
    },
    
    "healthcare": {
        "description": "HIPAA-compliant guardrails for healthcare",
        "input_guardrails": [
            {
                "class": "PHIAwarenessGuardrail",
                "config": {"severity": "critical"}
            },
            {
                "class": "PIIDetectionGuardrailExtended",
                "config": {"redact": True, "severity": "critical"}
            },
            {
                "class": "SecretsInInputGuardrail",
                "config": {"severity": "critical"}
            },
            {
                "class": "MedicalAdviceGuardrail",
                "config": {"block": False}  # Warn but don't block
            },
        ],
        "output_guardrails": [
            {
                "class": "OutputPIIRedactionGuardrail",
                "config": {}
            },
            {
                "class": "ConfidentialityGuardrail",
                "config": {}
            },
            {
                "class": "CitationRequiredGuardrail",
                "config": {"require_citations": True}
            },
        ],
        "tool_guardrails": []
    },
    
    "financial": {
        "description": "Financial services compliance guardrails",
        "input_guardrails": [
            {
                "class": "PIIDetectionGuardrailExtended",
                "config": {"redact": True, "severity": "critical"}
            },
            {
                "class": "SecretsInInputGuardrail",
                "config": {"severity": "critical"}
            },
            {
                "class": "DangerousPatternsGuardrail",
                "config": {"severity": "critical"}
            },
            {
                "class": "PromptInjectionSignatureGuardrail",
                "config": {"severity": "critical"}
            },
        ],
        "output_guardrails": [
            {
                "class": "OutputPIIRedactionGuardrail",
                "config": {}
            },
            {
                "class": "SecretLeakOutputGuardrail",
                "config": {}
            },
            {
                "class": "HallucinationRiskGuardrail",
                "config": {}
            },
        ],
        "tool_guardrails": [
            {
                "class": "DestructiveToolCallGuardrail",
                "config": {}
            },
        ]
    },
    
    "minimal": {
        "description": "Minimal guardrails for development/testing",
        "input_guardrails": [
            {
                "class": "InputSizeGuardrail",
                "config": {"max_chars": 100000}
            },
        ],
        "output_guardrails": [],
        "tool_guardrails": []
    },
}


def list_profiles():
    """List all available profiles"""
    return {
        name: profile["description"] 
        for name, profile in BUILTIN_PROFILES.items()
    }


def get_profile(name: str):
    """Get a profile by name"""
    return BUILTIN_PROFILES.get(name)