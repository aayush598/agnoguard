# agnoguard/guardrails/injection.py
import re
from typing import Dict, Any, Optional, List
from ..core.base import InputGuardrail, GuardrailResult, GuardrailAction, GuardrailSeverity


class PromptInjectionSignatureGuardrail(InputGuardrail):
    """Detects common prompt injection patterns"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.injection_patterns = [
            r'(?i)ignore\s+(previous|above|all|your)\s+(instructions?|rules?|commands?)',
            r'(?i)disregard\s+(previous|above|all)\s+(instructions?|rules?)',
            r'(?i)forget\s+(everything|all|what|your\s+instructions?)',
            r'(?i)new\s+(instructions?|task|role|mission)',
            r'(?i)(you\s+are|act\s+as)\s+now\s+(a|an)',
            r'(?i)system\s*:\s*',
            r'(?i)assistant\s*:\s*',
            r'(?i)\[SYSTEM\]|\[INST\]|\[/INST\]',
            r'(?i)override\s+(previous|all)\s+(settings|instructions)',
        ]
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        detected_patterns = []
        
        for pattern in self.injection_patterns:
            if re.search(pattern, content):
                detected_patterns.append(pattern)
        
        if detected_patterns:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.BLOCK,
                severity=GuardrailSeverity.CRITICAL,
                message=f"Prompt injection detected ({len(detected_patterns)} patterns)",
                metadata={"detected_count": len(detected_patterns)}
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="No injection patterns detected",
            metadata={}
        )


class SystemPromptLeakGuardrail(InputGuardrail):
    """Detects attempts to leak system prompts"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.leak_patterns = [
            r'(?i)show\s+(me\s+)?your\s+(system|initial|original)\s+(prompt|instructions?)',
            r'(?i)what\s+(are|is)\s+your\s+(system|initial)\s+(prompt|instructions?)',
            r'(?i)repeat\s+(your\s+)?instructions?',
            r'(?i)print\s+(your\s+)?(system|initial)\s+(prompt|instructions?)',
            r'(?i)display\s+(your\s+)?(system|hidden)\s+(prompt|instructions?)',
        ]
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        for pattern in self.leak_patterns:
            if re.search(pattern, content):
                return GuardrailResult(
                    passed=False,
                    action=GuardrailAction.BLOCK,
                    severity=GuardrailSeverity.CRITICAL,
                    message="System prompt leak attempt detected",
                    metadata={"pattern": pattern}
                )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="No leak attempts detected",
            metadata={}
        )


class JailbreakPatternGuardrail(InputGuardrail):
    """Detects jailbreak attempts like DAN, role-play attacks"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.jailbreak_keywords = [
            'DAN', 'do anything now', 'developer mode',
            'jailbreak', 'unrestricted', 'unfiltered',
            'token', 'stay in character', 'evil mode',
            'opposite mode', 'reverse mode'
        ]
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        content_lower = content.lower()
        found_keywords = [kw for kw in self.jailbreak_keywords if kw.lower() in content_lower]
        
        # Check for characteristic patterns
        has_multiple_keywords = len(found_keywords) >= 2
        has_dan = 'dan' in content_lower or 'do anything now' in content_lower
        
        if has_dan or has_multiple_keywords:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.BLOCK,
                severity=GuardrailSeverity.CRITICAL,
                message="Jailbreak attempt detected",
                metadata={"keywords": found_keywords}
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="No jailbreak patterns detected",
            metadata={}
        )


class RolePlayInjectionGuardrail(InputGuardrail):
    """Detects role-play based injection attempts"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.roleplay_patterns = [
            r'(?i)pretend\s+(you\s+are|to\s+be)',
            r'(?i)imagine\s+you\s+are',
            r'(?i)act\s+as\s+(if\s+)?you\s+(are|were)',
            r'(?i)simulate\s+(being|a)',
            r'(?i)roleplay\s+as',
            r'(?i)let\'s\s+play\s+a\s+game\s+where\s+you',
        ]
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        detected = []
        
        for pattern in self.roleplay_patterns:
            if re.search(pattern, content):
                detected.append(pattern)
        
        if detected:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.WARN,
                severity=GuardrailSeverity.WARNING,
                message="Role-play injection pattern detected",
                metadata={"patterns": len(detected)}
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="No role-play injection detected",
            metadata={}
        )


class OverrideInstructionGuardrail(InputGuardrail):
    """Detects attempts to override or change instructions"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.override_patterns = [
            r'(?i)new\s+(rule|instruction|command|directive)',
            r'(?i)from\s+now\s+on',
            r'(?i)instead\s+of\s+(following|obeying)',
            r'(?i)change\s+your\s+(behavior|rules|instructions)',
            r'(?i)update\s+your\s+(settings|configuration|rules)',
        ]
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        for pattern in self.override_patterns:
            if re.search(pattern, content):
                return GuardrailResult(
                    passed=False,
                    action=GuardrailAction.BLOCK,
                    severity=GuardrailSeverity.CRITICAL,
                    message="Instruction override attempt detected",
                    metadata={"pattern": pattern}
                )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="No override attempts detected",
            metadata={}
        )


class CrossContextManipulationGuardrail(InputGuardrail):
    """Detects attempts to manipulate context or memory"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.context_patterns = [
            r'(?i)previous\s+(conversation|context|chat)',
            r'(?i)earlier\s+in\s+(this|our)\s+conversation',
            r'(?i)(i|we)\s+(told|said|mentioned)\s+you\s+(earlier|before)',
            r'(?i)remember\s+when\s+(i|we)\s+said',
            r'(?i)as\s+(i|we)\s+established\s+earlier',
        ]
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        # Check if there's actual context
        has_context = context and context.get('conversation_history')
        
        if not has_context:
            # No context exists, check for manipulation
            for pattern in self.context_patterns:
                if re.search(pattern, content):
                    return GuardrailResult(
                        passed=False,
                        action=GuardrailAction.WARN,
                        severity=GuardrailSeverity.WARNING,
                        message="Context manipulation attempt (no prior context)",
                        metadata={"pattern": pattern}
                    )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="No context manipulation detected",
            metadata={}
        )


class LLMClassifierInjectionGuardrail(InputGuardrail):
    """Uses an LLM to classify if input contains injection attempts"""
    
    def __init__(self, threshold: float = 0.7, **kwargs):
        super().__init__(**kwargs)
        self.threshold = threshold
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        # Placeholder for actual LLM-based classification
        # In production, this would call an LLM API
        
        # For now, return a simple heuristic-based check
        suspicious_indicators = sum([
            'ignore' in content.lower(),
            'system' in content.lower(),
            'instructions' in content.lower(),
            len(content.split('\n')) > 10,  # Multi-line prompts
        ])
        
        score = suspicious_indicators / 4.0
        
        if score >= self.threshold:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.BLOCK,
                severity=GuardrailSeverity.ERROR,
                message=f"LLM classifier flagged input (score: {score:.2f})",
                metadata={"score": score, "threshold": self.threshold}
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="LLM classifier passed",
            metadata={"score": score}
        )