# agnoguard/guardrails/content_safety.py
import re
from typing import Dict, Any, Optional, List
from ..core.base import InputGuardrail, OutputGuardrail, ToolGuardrail
from ..core.base import GuardrailResult, GuardrailAction, GuardrailSeverity


class NSFWContentGuardrail(InputGuardrail):
    """Detects NSFW/adult content"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.nsfw_keywords = [
            'explicit', 'nude', 'nsfw', 'xxx', 'porn',
            'sexual', 'erotic', 'adult content'
        ]
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        content_lower = content.lower()
        found = [kw for kw in self.nsfw_keywords if kw in content_lower]
        
        if found:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.BLOCK,
                severity=GuardrailSeverity.CRITICAL,
                message="NSFW content detected",
                metadata={"keywords": found}
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="Content is safe",
            metadata={}
        )


class HateSpeechGuardrail(InputGuardrail):
    """Detects hate speech and discrimination"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Simplified for example - production should use ML models
        self.hate_indicators = ['hate', 'discriminate', 'slur', 'racist', 'bigot']
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        content_lower = content.lower()
        found = [ind for ind in self.hate_indicators if ind in content_lower]
        
        if len(found) >= 2:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.BLOCK,
                severity=GuardrailSeverity.CRITICAL,
                message="Potential hate speech detected",
                metadata={"indicators": found}
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="No hate speech detected",
            metadata={}
        )


class ViolenceGuardrail(InputGuardrail):
    """Detects violent content"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.violence_keywords = [
            'kill', 'murder', 'harm', 'attack', 'violent',
            'assault', 'weapon', 'bomb', 'torture'
        ]
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        content_lower = content.lower()
        found = [kw for kw in self.violence_keywords if kw in content_lower]
        
        if len(found) >= 3:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.WARN,
                severity=GuardrailSeverity.WARNING,
                message="Violent content detected",
                metadata={"keywords": found}
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="No violent content",
            metadata={}
        )


class SelfHarmGuardrail(InputGuardrail):
    """Detects self-harm content"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.selfharm_patterns = [
            r'(?i)self[- ]?harm',
            r'(?i)suicid(e|al)',
            r'(?i)end\s+my\s+life',
            r'(?i)want\s+to\s+die',
        ]
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        for pattern in self.selfharm_patterns:
            if re.search(pattern, content):
                return GuardrailResult(
                    passed=False,
                    action=GuardrailAction.BLOCK,
                    severity=GuardrailSeverity.CRITICAL,
                    message="Self-harm content detected - please seek help",
                    metadata={"pattern": pattern, "resources": "988 Suicide & Crisis Lifeline"}
                )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="No self-harm content",
            metadata={}
        )


class MedicalAdviceGuardrail(InputGuardrail):
    """Warns when medical advice is being requested"""
    
    def __init__(self, block: bool = False, **kwargs):
        super().__init__(**kwargs)
        self.block = block
        self.medical_patterns = [
            r'(?i)diagnose\s+me',
            r'(?i)what\s+medication',
            r'(?i)should\s+i\s+take\s+(medicine|drug|pill)',
            r'(?i)medical\s+advice',
        ]
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        for pattern in self.medical_patterns:
            if re.search(pattern, content):
                action = GuardrailAction.BLOCK if self.block else GuardrailAction.WARN
                return GuardrailResult(
                    passed=not self.block,
                    action=action,
                    severity=GuardrailSeverity.WARNING,
                    message="Medical advice request detected - consult healthcare professional",
                    metadata={"pattern": pattern}
                )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="No medical advice request",
            metadata={}
        )


# Tool Guardrails
class ToolAccessControlGuardrail(ToolGuardrail):
    """Controls which tools can be accessed"""
    
    def __init__(self, allowed_tools: Optional[List[str]] = None, blocked_tools: Optional[List[str]] = None, **kwargs):
        super().__init__(**kwargs)
        self.allowed_tools = allowed_tools
        self.blocked_tools = blocked_tools or []
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        # This is for text content, not direct tool calls
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="Tool access check passed",
            metadata={}
        )
    
    def check_tool_call(self, tool_name: str, tool_args: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        if tool_name in self.blocked_tools:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.BLOCK,
                severity=GuardrailSeverity.ERROR,
                message=f"Tool '{tool_name}' is blocked",
                metadata={"tool": tool_name}
            )
        
        if self.allowed_tools and tool_name not in self.allowed_tools:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.BLOCK,
                severity=GuardrailSeverity.ERROR,
                message=f"Tool '{tool_name}' is not in allowed list",
                metadata={"tool": tool_name}
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message=f"Tool '{tool_name}' access granted",
            metadata={"tool": tool_name}
        )


class DestructiveToolCallGuardrail(ToolGuardrail):
    """Prevents destructive tool operations"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.destructive_operations = ['delete', 'remove', 'drop', 'truncate', 'destroy']
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        return GuardrailResult(passed=True, action=GuardrailAction.ALLOW, 
                             severity=GuardrailSeverity.INFO, message="OK", metadata={})
    
    def check_tool_call(self, tool_name: str, tool_args: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        # Check tool name and arguments for destructive operations
        tool_name_lower = tool_name.lower()
        args_str = str(tool_args).lower()
        
        is_destructive = any(op in tool_name_lower or op in args_str 
                            for op in self.destructive_operations)
        
        if is_destructive:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.BLOCK,
                severity=GuardrailSeverity.CRITICAL,
                message=f"Destructive operation blocked: {tool_name}",
                metadata={"tool": tool_name, "args": tool_args}
            )
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="Non-destructive operation",
            metadata={}
        )


class RateLimitGuardrail(InputGuardrail):
    """Rate limits requests"""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60, **kwargs):
        super().__init__(**kwargs)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.request_history = {}
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        import time
        
        user_id = context.get('user_id', 'anonymous') if context else 'anonymous'
        current_time = time.time()
        
        # Initialize or clean history
        if user_id not in self.request_history:
            self.request_history[user_id] = []
        
        # Remove old requests
        self.request_history[user_id] = [
            t for t in self.request_history[user_id] 
            if current_time - t < self.window_seconds
        ]
        
        # Check rate limit
        if len(self.request_history[user_id]) >= self.max_requests:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.BLOCK,
                severity=GuardrailSeverity.ERROR,
                message=f"Rate limit exceeded: {self.max_requests} requests per {self.window_seconds}s",
                metadata={"requests": len(self.request_history[user_id]), "limit": self.max_requests}
            )
        
        # Add current request
        self.request_history[user_id].append(current_time)
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message="Rate limit OK",
            metadata={"requests": len(self.request_history[user_id]), "limit": self.max_requests}
        )


class CostThresholdGuardrail(InputGuardrail):
    """Monitors and limits costs"""
    
    def __init__(self, max_cost: float = 1.0, cost_per_request: float = 0.01, **kwargs):
        super().__init__(**kwargs)
        self.max_cost = max_cost
        self.cost_per_request = cost_per_request
        self.accumulated_cost = {}
    
    def check(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        user_id = context.get('user_id', 'anonymous') if context else 'anonymous'
        
        # Initialize cost tracking
        if user_id not in self.accumulated_cost:
            self.accumulated_cost[user_id] = 0.0
        
        # Check if adding this request would exceed threshold
        new_cost = self.accumulated_cost[user_id] + self.cost_per_request
        
        if new_cost > self.max_cost:
            return GuardrailResult(
                passed=False,
                action=GuardrailAction.BLOCK,
                severity=GuardrailSeverity.ERROR,
                message=f"Cost threshold exceeded: ${new_cost:.2f} > ${self.max_cost:.2f}",
                metadata={"cost": new_cost, "threshold": self.max_cost}
            )
        
        # Increment cost
        self.accumulated_cost[user_id] = new_cost
        
        return GuardrailResult(
            passed=True,
            action=GuardrailAction.ALLOW,
            severity=GuardrailSeverity.INFO,
            message=f"Cost within threshold: ${new_cost:.2f}",
            metadata={"cost": new_cost, "threshold": self.max_cost}
        )