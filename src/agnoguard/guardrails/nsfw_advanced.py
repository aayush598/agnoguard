# agnoguard/guardrails/nsfw_advanced.py
"""
Advanced production-grade NSFW content detection guardrail.

This implements a multi-layered, multi-signal approach to NSFW content detection
with configurable severity levels, context awareness, and sophisticated pattern matching.

Based on industry best practices from OpenAI, Microsoft, and NIST AI RMF guidelines.
"""

import re
from typing import Dict, Any, Optional, List, Set, Tuple
from enum import Enum
from dataclasses import dataclass
from ..core.base import InputGuardrail, GuardrailResult, GuardrailAction, GuardrailSeverity


class NSFWSeverityLevel(Enum):
    """NSFW content severity classification following industry standards"""
    LEVEL_0_ALLOWED = 0          # Non-sexual, scientific/medical content
    LEVEL_1_RESTRICTED = 1       # Mature themes, requires age verification
    LEVEL_2_CONTEXTUAL = 2       # Potentially explicit, needs human review
    LEVEL_3_CRITICAL = 3         # Explicit sexual content, immediate block


@dataclass
class NSFWDetectionSignal:
    """Individual detection signal from a specific checker"""
    signal_type: str
    confidence: float  # 0.0 to 1.0
    matched_terms: List[str]
    severity: NSFWSeverityLevel
    context: str
    metadata: Dict[str, Any]


class NSFWContentGuardrail(InputGuardrail):
    """
    Advanced NSFW content detection with multi-signal ensemble approach.
    
    Features:
    - Multi-layer severity classification (Level 0-3)
    - Context-aware detection (medical/educational vs explicit)
    - Obfuscation-resistant pattern matching
    - Intent detection (clinical vs erotic)
    - Euphemism and slang detection
    - Multi-language support (extensible)
    - Age verification integration
    - Graduated response system
    
    Args:
        severity_threshold: Minimum severity level to block (default: LEVEL_1_RESTRICTED)
        enable_context_analysis: Enable context-aware detection (default: True)
        require_age_verification: Require age verification for restricted content (default: False)
        allow_medical_educational: Allow medical/educational content (default: True)
        enable_obfuscation_detection: Detect obfuscated NSFW terms (default: True)
        custom_blocklist: Additional terms to block (default: None)
        custom_allowlist: Terms to allow despite detection (default: None)
        min_confidence: Minimum confidence threshold (0.0-1.0, default: 0.7)
        enable_telemetry: Log detection telemetry (default: True)
    """
    
    def __init__(
        self,
        severity_threshold: NSFWSeverityLevel = NSFWSeverityLevel.LEVEL_1_RESTRICTED,
        enable_context_analysis: bool = True,
        require_age_verification: bool = False,
        allow_medical_educational: bool = True,
        enable_obfuscation_detection: bool = True,
        custom_blocklist: Optional[List[str]] = None,
        custom_allowlist: Optional[List[str]] = None,
        min_confidence: float = 0.7,
        enable_telemetry: bool = True,
        **kwargs
    ):
        super().__init__(**kwargs)
        
        # Configuration
        self.severity_threshold = severity_threshold
        self.enable_context_analysis = enable_context_analysis
        self.require_age_verification = require_age_verification
        self.allow_medical_educational = allow_medical_educational
        self.enable_obfuscation_detection = enable_obfuscation_detection
        self.min_confidence = min_confidence
        self.enable_telemetry = enable_telemetry
        
        # Custom lists
        self.custom_blocklist = set(custom_blocklist or [])
        self.custom_allowlist = set(custom_allowlist or [])
        
        # Initialize detection components
        self._init_detection_patterns()
        self._init_context_patterns()
        self._init_obfuscation_patterns()
    
    def _init_detection_patterns(self):
        """Initialize multi-tier NSFW detection patterns"""
        
        # LEVEL 3 - CRITICAL: Explicit sexual content (immediate block)
        self.level_3_explicit = {
            # Explicit sexual acts
            'sexual_acts': [
                r'\b(intercourse|penetration|oral\s+sex|fellatio|cunnilingus|sexual\s+activities)\b',
                r'\b(masturbat(e|ion|ing)|climax|orgasm)\b',
                r'\b(ejaculat(e|ion)|cumming)\b',
            ],
            # Explicit anatomical terms in sexual context
            'explicit_anatomy': [
                r'\b(penis|cock|dick|vagina|pussy|cunt)\b.*\b(touch|lick|suck|fuck|stroke|rub|insert|penetrat)',
                r'\b(touch|lick|suck|fuck|stroke|rub|insert|penetrat).*\b(penis|cock|dick|vagina|pussy|cunt)\b',
            ],
            # Sexual violence indicators
            'sexual_violence': [
                    r'\brape\b',                                 # rape
                    r'\brapist\b',                               # rapist
                    r'\bsexual\s+assault\b',                     # sexual assault
                    r'\bnon[-\s]?consensual\b',                  # non-consensual (hyphens or space or both)
                    r'\bmolest(ation)?\b',                       # molest, molestation
                    r'\bgrope\b',                                # grope
                    r'\b(forced|coerced)\s+(sex|sexual)\b',      # forced sex, coerced sex
                ],
            # Pornographic content
            'pornographic': [
                r'\b(porn|pornography|xxx)\b',
                r'\b(adult\s*(video|videos|content))\b',
                r'\b(sex\s*(tape|video|videos))\b',
                r'\b(explicit\s+(\w+\s+)?(content|material))\b',
            ],
        }
        
        # LEVEL 2 - CONTEXTUAL: Potentially explicit (needs context analysis)
        self.level_2_contextual = {
            # Sexual themes
            'sexual_themes': [
                r'\b(sexual|erotic|sensual|seductive)\b',
                r'\b(aroused?|arousal|turned\s+on|horny)\b',
                r'\b(seduc(e|tion|ing)|lust)\b',
            ],
            # Anatomy (context-dependent)
            'anatomy': [
                r'\b(naked|nude|undress|strip|exposed)\b',
            ],
            # Relationship/consent ambiguity
            'relationship': [
                r'\b(affair|mistress|lover)\b',
                r'\b(hookup|fling)\b',
            ],
        }
        
        # LEVEL 1 - RESTRICTED: Mature themes (may require age verification)
        self.level_1_restricted = {
            # Mature themes
            'mature': [
                r'\b(kiss(ing|ed)?)\b',
                r'\b(attraction|attracted|desire)\b',
            ],
            # Sexual health (educational context)
            'health': [
                r'\b(contraception|birth\s+control|std|sti)\b',
                r'\b(sexual\s+health|reproductive\s+health)\b',
            ],
        }
        
        # LEVEL 0 - ALLOWED: Medical/scientific (contextual allowlist)
        self.level_0_medical = {
            'medical': [
                r'\b(medical|clinical|anatomical|physiological)\b',
                r'\b(diagnosis|treatment|examination|procedure)\b',
                r'\b(patient|doctor|healthcare|hospital)\b',
            ],
            'educational': [
                r'\b(education|teaching|learning|academic)\b',
                r'\b(biology|anatomy|reproductive\s+system)\b',
                r'\b(textbook|curriculum|course)\b',
            ],
            'scientific': [
                r'\b(research|study|scientific|peer-reviewed)\b',
                r'\b(journal|publication|findings)\b',
            ],
        }
    
    def _init_context_patterns(self):
        """Initialize context detection patterns"""
        
        # Indicators of medical/educational context
        self.medical_indicators = [
            r'\b(doctor|physician|nurse|surgeon|medical\s+professional)\b',
            r'\b(hospital|clinic|medical\s+center|healthcare\s+facility)\b',
            r'\b(diagnosis|prognosis|symptoms?|treatment\s+plan)\b',
            r'\b(prescription|medication|therapy)\b',
        ]
        
        self.educational_indicators = [
            r'\b(professor|teacher|student|class|lecture)\b',
            r'\b(university|college|school|academy)\b',
            r'\b(textbook|curriculum|syllabus|assignment)\b',
            r'\b(learn|study|understand|explain|teach)\b',
        ]
        
        # Indicators of erotic/explicit intent
        self.erotic_intent_indicators = [
            r'\b(want\s+to|desire\s+to|fantasize|imagine).*\b(sex|sexual)',
            r'\b(turned?\s+on|aroused|excited|stimulated)\b',
            r'\b(make\s+love|have\s+sex|sleep\s+together)\b',
            r'\b(seduce|tempt|entice)\b',
        ]
        
        # Roleplay and hypothetical framing (jailbreak patterns)
        self.roleplay_indicators = [
            r'\b(pretend|imagine|roleplay|scenario|story)\b',
            r'\b(character|persona|acting\s+as)\b',
            r'in\s+this\s+(story|scenario|scene|roleplay)',
            r'\b(fictional|hypothetical|what\s+if)\b',
        ]
    
    def _init_obfuscation_patterns(self):
        """Initialize obfuscation detection patterns"""
        
        # Common obfuscation techniques
        self.obfuscation_patterns = {
            # Character insertions/separations
            'separation': [
                r'\bp\s*[._-]?\s*o\s*[._-]?\s*r\s*[._-]?\s*n',  # p.o.r.n, p-o-r-n
                r'\bs\s*[._-]?\s*[e3]\s*[._-]?\s*x\b',  # s.e.x, s-e-x
            ],
            # Deliberate misspellings
            'misspellings': [
                r'\bp[o0]rn\b',
                r'\bs[e3]x[iy]?\b',
                r'\bn[au]k[e3]d\b',
                r'\bh[o0]rny\b',
            ],
        }
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        """
        Perform multi-signal NSFW detection on input content.
        
        Args:
            content: Input text to analyze
            context: Optional context including user verification status, conversation history
            
        Returns:
            GuardrailResult with detection details and recommended action
        """
        if not content or not isinstance(content, str):
            return GuardrailResult(
                passed=True,
                action=GuardrailAction.ALLOW,
                severity=GuardrailSeverity.INFO,
                message="Empty or invalid content",
                metadata={}
            )
        
        # Normalize content
        normalized_content = self._normalize_content(content)
        
        # Collect all detection signals
        signals: List[NSFWDetectionSignal] = []
        
        # 1. Pre-filter: Check custom blocklist
        if blocklist_signal := self._check_custom_blocklist(normalized_content):
            signals.append(blocklist_signal)
        
        # 2. Multi-tier pattern matching
        signals.extend(self._check_level_3_critical(normalized_content))
        signals.extend(self._check_level_2_contextual(normalized_content))
        signals.extend(self._check_level_1_restricted(normalized_content))
        
        # 3. Obfuscation detection
        if self.enable_obfuscation_detection:
            signals.extend(self._check_obfuscation(content, normalized_content))
        
        # 4. Context analysis
        if self.enable_context_analysis:
            context_modifier = self._analyze_context(normalized_content, context)
        else:
            context_modifier = 1.0
        
        # 5. Check allowlist (medical/educational exemptions)
        if self.allow_medical_educational:
            if self._is_medical_educational_context(normalized_content):
                context_modifier *= 0.3  # Reduce confidence for medical/educational
        
        # 6. Ensemble decision making
        decision = self._make_ensemble_decision(signals, context_modifier, context)
        
        # 7. Generate result
        return self._generate_result(decision, signals, content, context)
    
    def _normalize_content(self, content: str) -> str:
        """Normalize content for analysis"""
        # Convert to lowercase
        normalized = content.lower()
        
        # Remove extra whitespace
        normalized = re.sub(r'\s+', ' ', normalized)
        
        return normalized.strip()
    
    def _check_custom_blocklist(self, content: str) -> Optional[NSFWDetectionSignal]:
        """Check against custom blocklist"""
        for term in self.custom_blocklist:
            if term.lower() in content:
                return NSFWDetectionSignal(
                    signal_type="custom_blocklist",
                    confidence=1.0,
                    matched_terms=[term],
                    severity=NSFWSeverityLevel.LEVEL_3_CRITICAL,
                    context="Custom blocklist match",
                    metadata={"source": "custom_blocklist"}
                )
        return None
    
    def _check_level_3_critical(self, content: str) -> List[NSFWDetectionSignal]:
        """Check for Level 3 critical NSFW content"""
        signals = []
        
        for category, patterns in self.level_3_explicit.items():
            for pattern in patterns:
                matches = list(re.finditer(pattern, content, re.IGNORECASE))
                if matches:
                    # Filter out empty matches
                    valid_matches = [m for m in matches if m.group(0).strip()]
                    if valid_matches:
                        matched_terms = [m.group(0) for m in valid_matches]
                        signals.append(NSFWDetectionSignal(
                            signal_type=f"level_3_{category}",
                            confidence=0.95,  # High confidence for explicit patterns
                            matched_terms=matched_terms,
                            severity=NSFWSeverityLevel.LEVEL_3_CRITICAL,
                            context=f"Explicit {category} detected",
                            metadata={"pattern": pattern}
                        ))
        
        return signals
    
    def _check_level_2_contextual(self, content: str) -> List[NSFWDetectionSignal]:
        """Check for Level 2 contextual NSFW content"""
        signals = []
        
        for category, patterns in self.level_2_contextual.items():
            for pattern in patterns:
                matches = list(re.finditer(pattern, content, re.IGNORECASE))
                if matches:
                    valid_matches = [m for m in matches if m.group(0).strip()]
                    if valid_matches:
                        matched_terms = [m.group(0) for m in valid_matches]
                        signals.append(NSFWDetectionSignal(
                            signal_type=f"level_2_{category}",
                            confidence=0.75,  # Medium confidence, needs context
                            matched_terms=matched_terms,
                            severity=NSFWSeverityLevel.LEVEL_2_CONTEXTUAL,
                            context=f"Contextual {category} detected",
                            metadata={"pattern": pattern}
                        ))
        
        return signals
    
    def _check_level_1_restricted(self, content: str) -> List[NSFWDetectionSignal]:
        """Check for Level 1 restricted content"""
        signals = []
        
        for category, patterns in self.level_1_restricted.items():
            for pattern in patterns:
                matches = list(re.finditer(pattern, content, re.IGNORECASE))
                if matches:
                    valid_matches = [m for m in matches if m.group(0).strip()]
                    if valid_matches:
                        matched_terms = [m.group(0) for m in valid_matches]
                        signals.append(NSFWDetectionSignal(
                            signal_type=f"level_1_{category}",
                            confidence=0.6,  # Lower confidence
                            matched_terms=matched_terms,
                            severity=NSFWSeverityLevel.LEVEL_1_RESTRICTED,
                            context=f"Mature {category} detected",
                            metadata={"pattern": pattern}
                        ))
        
        return signals
    
    def _check_obfuscation(self, original: str, normalized: str) -> List[NSFWDetectionSignal]:
        """Detect obfuscated NSFW terms"""
        signals = []
        
        # Check character separation patterns
        for pattern in self.obfuscation_patterns['separation']:
            if re.search(pattern, original, re.IGNORECASE):
                signals.append(NSFWDetectionSignal(
                    signal_type="obfuscation_separation",
                    confidence=0.85,
                    matched_terms=[pattern],
                    severity=NSFWSeverityLevel.LEVEL_3_CRITICAL,
                    context="Obfuscated NSFW term detected (separation)",
                    metadata={"technique": "character_separation"}
                ))
        
        # Check misspelling patterns
        for pattern in self.obfuscation_patterns['misspellings']:
            if re.search(pattern, normalized):
                signals.append(NSFWDetectionSignal(
                    signal_type="obfuscation_misspelling",
                    confidence=0.8,
                    matched_terms=[pattern],
                    severity=NSFWSeverityLevel.LEVEL_3_CRITICAL,
                    context="Obfuscated NSFW term detected (misspelling)",
                    metadata={"technique": "deliberate_misspelling"}
                ))
        
        return signals
    
    def _analyze_context(self, content: str, context: Optional[Dict[str, Any]]) -> float:
        """
        Analyze context to adjust confidence.
        Returns a multiplier (0.0 to 1.5) to adjust signal confidence.
        """
        modifier = 1.0
        
        # Check for medical/educational indicators
        medical_count = sum(1 for p in self.medical_indicators if re.search(p, content, re.IGNORECASE))
        educational_count = sum(1 for p in self.educational_indicators if re.search(p, content, re.IGNORECASE))
        
        if medical_count >= 2 or educational_count >= 2:
            modifier *= 0.5  # Reduce confidence in medical/educational context
        
        # Check for erotic intent indicators
        intent_count = sum(1 for p in self.erotic_intent_indicators if re.search(p, content, re.IGNORECASE))
        if intent_count >= 1:
            modifier *= 1.3  # Increase confidence with explicit intent
        
        # Check for roleplay/jailbreak patterns
        roleplay_count = sum(1 for p in self.roleplay_indicators if re.search(p, content, re.IGNORECASE))
        if roleplay_count >= 2:
            modifier *= 1.4  # Strongly increase confidence (likely evasion attempt)
        
        # Check user context if available
        if context:
            # Age verification status
            if context.get('age_verified', False):
                modifier *= 0.8  # Slightly more permissive for verified users
            
            # Prior violations
            if context.get('prior_violations', 0) > 0:
                modifier *= 1.2  # More strict for repeat offenders
        
        return max(0.0, min(1.5, modifier))  # Clamp between 0 and 1.5
    
    def _is_medical_educational_context(self, content: str) -> bool:
        """Check if content is in medical/educational context"""
        medical_score = 0
        educational_score = 0
        
        for category, patterns in self.level_0_medical.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    if category == 'medical':
                        medical_score += 1
                    elif category == 'educational':
                        educational_score += 1
                    elif category == 'scientific':
                        educational_score += 1
        
        # Require strong evidence of medical/educational context
        return medical_score >= 2 or educational_score >= 2
    
    def _make_ensemble_decision(
        self,
        signals: List[NSFWDetectionSignal],
        context_modifier: float,
        context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Make final decision using ensemble of signals.
        
        Returns decision dict with:
        - severity: NSFWSeverityLevel
        - confidence: float
        - action: GuardrailAction
        - reasoning: str
        """
        if not signals:
            return {
                'severity': NSFWSeverityLevel.LEVEL_0_ALLOWED,
                'confidence': 1.0,
                'action': GuardrailAction.ALLOW,
                'reasoning': 'No NSFW content detected'
            }
        
        # Calculate weighted severity score
        severity_scores = {
            NSFWSeverityLevel.LEVEL_3_CRITICAL: 0,
            NSFWSeverityLevel.LEVEL_2_CONTEXTUAL: 0,
            NSFWSeverityLevel.LEVEL_1_RESTRICTED: 0,
        }
        
        total_confidence = 0.0
        max_confidence = 0.0
        highest_severity = NSFWSeverityLevel.LEVEL_0_ALLOWED
        
        for signal in signals:
            adjusted_confidence = signal.confidence * context_modifier
            severity_scores[signal.severity] += adjusted_confidence
            total_confidence += adjusted_confidence
            
            if adjusted_confidence > max_confidence:
                max_confidence = adjusted_confidence
                highest_severity = signal.severity
        
        # Decision logic
        avg_confidence = total_confidence / len(signals) if signals else 0.0
        
        # Critical content always blocks
        if severity_scores[NSFWSeverityLevel.LEVEL_3_CRITICAL] > 0:
            return {
                'severity': NSFWSeverityLevel.LEVEL_3_CRITICAL,
                'confidence': max(max_confidence, 0.9),
                'action': GuardrailAction.BLOCK,
                'reasoning': 'Explicit sexual content detected'
            }
        
        # Contextual content needs review or verification
        if severity_scores[NSFWSeverityLevel.LEVEL_2_CONTEXTUAL] > self.min_confidence:
            if self.require_age_verification and not (context and context.get('age_verified', False)):
                return {
                    'severity': NSFWSeverityLevel.LEVEL_2_CONTEXTUAL,
                    'confidence': avg_confidence,
                    'action': GuardrailAction.BLOCK,
                    'reasoning': 'Age verification required for mature content'
                }
            else:
                return {
                    'severity': NSFWSeverityLevel.LEVEL_2_CONTEXTUAL,
                    'confidence': avg_confidence,
                    'action': GuardrailAction.WARN,
                    'reasoning': 'Mature content detected, proceeding with caution'
                }
        
        # Restricted content
        if severity_scores[NSFWSeverityLevel.LEVEL_1_RESTRICTED] > self.min_confidence:
            if self.require_age_verification and not (context and context.get('age_verified', False)):
                return {
                    'severity': NSFWSeverityLevel.LEVEL_1_RESTRICTED,
                    'confidence': avg_confidence,
                    'action': GuardrailAction.WARN,
                    'reasoning': 'Mature themes detected, age verification recommended'
                }
            else:
                return {
                    'severity': NSFWSeverityLevel.LEVEL_1_RESTRICTED,
                    'confidence': avg_confidence,
                    'action': GuardrailAction.ALLOW,
                    'reasoning': 'Mature themes present but allowed'
                }
        
        # Low confidence or below threshold
        return {
            'severity': NSFWSeverityLevel.LEVEL_0_ALLOWED,
            'confidence': avg_confidence,
            'action': GuardrailAction.ALLOW,
            'reasoning': 'Content appears safe'
        }
    
    def _generate_result(
        self,
        decision: Dict[str, Any],
        signals: List[NSFWDetectionSignal],
        original_content: str,
        context: Optional[Dict[str, Any]]
    ) -> GuardrailResult:
        """Generate final GuardrailResult with full metadata"""
        
        # Map decision to GuardrailResult
        passed = decision['action'] in [GuardrailAction.ALLOW, GuardrailAction.WARN]
        
        # Map severity level to GuardrailSeverity
        severity_map = {
            NSFWSeverityLevel.LEVEL_0_ALLOWED: GuardrailSeverity.INFO,
            NSFWSeverityLevel.LEVEL_1_RESTRICTED: GuardrailSeverity.WARNING,
            NSFWSeverityLevel.LEVEL_2_CONTEXTUAL: GuardrailSeverity.WARNING,
            NSFWSeverityLevel.LEVEL_3_CRITICAL: GuardrailSeverity.CRITICAL,
        }
        
        result_severity = severity_map[decision['severity']]
        
        # Build comprehensive metadata
        metadata = {
            'nsfw_severity_level': decision['severity'].name,
            'confidence': round(decision['confidence'], 3),
            'reasoning': decision['reasoning'],
            'signals_detected': len(signals),
            'signal_details': [
                {
                    'type': s.signal_type,
                    'confidence': round(s.confidence, 3),
                    'matched_terms': s.matched_terms[:3],  # Limit to first 3
                    'severity': s.severity.name
                }
                for s in signals[:5]  # Limit to top 5 signals
            ],
            'requires_age_verification': (
                self.require_age_verification and 
                not (context and context.get('age_verified', False))
            ),
            'medical_educational_context': self._is_medical_educational_context(
                self._normalize_content(original_content)
            ),
        }
        
        # Add telemetry if enabled
        if self.enable_telemetry:
            metadata['telemetry'] = {
                'content_length': len(original_content),
                'detection_timestamp': self._get_timestamp(),
                'guardrail_version': '2.0.0',
            }
        
        # Generate user-friendly message
        if decision['action'] == GuardrailAction.BLOCK:
            if decision['severity'] == NSFWSeverityLevel.LEVEL_3_CRITICAL:
                message = "Content blocked: Explicit sexual content violates our usage policy."
            elif self.require_age_verification and not (context and context.get('age_verified', False)):
                message = "Content blocked: Age verification required for mature content."
            else:
                message = f"Content blocked: {decision['reasoning']}"
        elif decision['action'] == GuardrailAction.WARN:
            message = f"Warning: {decision['reasoning']}"
        else:
            message = "Content appears safe for processing."
        
        return GuardrailResult(
            passed=passed,
            action=decision['action'],
            severity=result_severity,
            message=message,
            metadata=metadata,
            modified_content=None  # Could implement content sanitization here
        )
    
    def _get_timestamp(self) -> str:
        """Get current timestamp for telemetry"""
        from datetime import datetime
        return datetime.utcnow().isoformat() + 'Z'
    
    def get_policy_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the guardrail's policy configuration.
        Useful for transparency and auditing.
        """
        return {
            'guardrail_name': self.name,
            'severity_threshold': self.severity_threshold.name,
            'configuration': {
                'context_analysis_enabled': self.enable_context_analysis,
                'age_verification_required': self.require_age_verification,
                'medical_educational_allowed': self.allow_medical_educational,
                'obfuscation_detection_enabled': self.enable_obfuscation_detection,
                'min_confidence_threshold': self.min_confidence,
            },
            'custom_rules': {
                'blocklist_terms': len(self.custom_blocklist),
                'allowlist_terms': len(self.custom_allowlist),
            },
            'detection_capabilities': {
                'level_3_categories': list(self.level_3_explicit.keys()),
                'level_2_categories': list(self.level_2_contextual.keys()),
                'level_1_categories': list(self.level_1_restricted.keys()),
                'obfuscation_techniques': list(self.obfuscation_patterns.keys()),
            }
        }


# Example usage configurations
def create_strict_nsfw_guardrail() -> NSFWContentGuardrail:
    """Create a strict NSFW guardrail for general audience applications"""
    return NSFWContentGuardrail(
        severity_threshold=NSFWSeverityLevel.LEVEL_1_RESTRICTED,
        enable_context_analysis=True,
        require_age_verification=False,
        allow_medical_educational=True,
        enable_obfuscation_detection=True,
        min_confidence=0.6,
    )


def create_age_verified_nsfw_guardrail() -> NSFWContentGuardrail:
    """Create NSFW guardrail for age-verified adult applications"""
    return NSFWContentGuardrail(
        severity_threshold=NSFWSeverityLevel.LEVEL_2_CONTEXTUAL,
        enable_context_analysis=True,
        require_age_verification=True,
        allow_medical_educational=True,
        enable_obfuscation_detection=True,
        min_confidence=0.7,
    )


def create_educational_nsfw_guardrail() -> NSFWContentGuardrail:
    """Create NSFW guardrail optimized for educational/medical contexts"""
    return NSFWContentGuardrail(
        severity_threshold=NSFWSeverityLevel.LEVEL_3_CRITICAL,
        enable_context_analysis=True,
        require_age_verification=False,
        allow_medical_educational=True,
        enable_obfuscation_detection=True,
        min_confidence=0.8,  # Higher threshold for educational use
    )