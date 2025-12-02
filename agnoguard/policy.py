# agnoguard/policy.py
"""
Policy-based guardrail application for Agno teams
"""
from typing import Any, Optional
from .suite import GuardrailSuite


def apply_policy(team: Any, policy_name: str, **kwargs) -> Any:
    """
    Apply a guardrail policy to an Agno team
    
    Args:
        team: The Agno Team instance
        policy_name: Name of the policy profile to apply
        **kwargs: Additional configuration options
        
    Returns:
        The team with guardrails applied
    
    Example:
        team = Team(...)
        team = apply_policy(team, "enterprise_security")
    """
    suite = GuardrailSuite.load_profile(policy_name)
    
    # Apply pre-hooks (input guardrails)
    if hasattr(team, 'pre_hooks'):
        if not isinstance(team.pre_hooks, list):
            team.pre_hooks = []
        team.pre_hooks.extend(suite.pre_hooks)
    else:
        team.pre_hooks = suite.pre_hooks
    
    # Apply post-hooks (output guardrails)
    if hasattr(team, 'post_hooks'):
        if not isinstance(team.post_hooks, list):
            team.post_hooks = []
        team.post_hooks.extend(suite.post_hooks)
    else:
        team.post_hooks = suite.post_hooks
    
    return team


class PolicyBuilder:
    """Builder for creating custom policies"""
    
    def __init__(self, name: str = "custom"):
        self.name = name
        self.input_guardrails = []
        self.output_guardrails = []
        self.tool_guardrails = []
    
    def add_input_guardrail(self, guardrail):
        """Add an input guardrail"""
        self.input_guardrails.append(guardrail)
        return self
    
    def add_output_guardrail(self, guardrail):
        """Add an output guardrail"""
        self.output_guardrails.append(guardrail)
        return self
    
    def add_tool_guardrail(self, guardrail):
        """Add a tool guardrail"""
        self.tool_guardrails.append(guardrail)
        return self
    
    def build(self) -> GuardrailSuite:
        """Build the guardrail suite"""
        suite = GuardrailSuite("custom")
        suite.input_guardrails = self.input_guardrails
        suite.output_guardrails = self.output_guardrails
        suite.tool_guardrails = self.tool_guardrails
        return suite
    
    def apply_to(self, team: Any) -> Any:
        """Build and apply to a team"""
        suite = self.build()
        return apply_policy_suite(team, suite)


def apply_policy_suite(team: Any, suite: GuardrailSuite) -> Any:
    """Apply a guardrail suite directly to a team"""
    if hasattr(team, 'pre_hooks'):
        if not isinstance(team.pre_hooks, list):
            team.pre_hooks = []
        team.pre_hooks.extend(suite.pre_hooks)
    else:
        team.pre_hooks = suite.pre_hooks
    
    if hasattr(team, 'post_hooks'):
        if not isinstance(team.post_hooks, list):
            team.post_hooks = []
        team.post_hooks.extend(suite.post_hooks)
    else:
        team.post_hooks = suite.post_hooks
    
    return team