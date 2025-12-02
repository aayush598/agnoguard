# AgnoGuard

**Comprehensive LLM Guardrails for Agno Framework**

AgnoGuard provides 50+ production-ready guardrails for securing and controlling LLM applications built with Agno. Protect against prompt injection, prevent data leakage, ensure content safety, and maintain compliance with minimal code.

## Quick Start

```bash
pip install agnoguard
```

### Basic Usage

```python
from agnoguard import GuardrailSuite
from agno import Team

# Apply default guardrails
team = Team(
    name="My Team",
    agents=[...],
    pre_hooks=GuardrailSuite("default").pre_hooks
)
```

### Enterprise Security

```python
from agnoguard import GuardrailSuite

suite = GuardrailSuite.load_profile("enterprise_security")
team = Team(
    name="Enterprise Team",
    agents=[...],
    pre_hooks=suite.inputs,
    post_hooks=suite.outputs
)
```

### Policy-Based Application

```python
from agnoguard.policy import apply_policy

team = Team(name="Protected Team", agents=[...])
team = apply_policy(team, "child_safety")
```

## Features

### Input Validation Guardrails
- **PIIDetectionGuardrailExtended** - Detect and redact SSN, credit cards, emails, phone numbers
- **PHIAwarenessGuardrail** - Protected Health Information detection
- **URLAndFileBlockerGuardrail** - Block URLs and file paths
- **SecretsInInputGuardrail** - Detect API keys, tokens, passwords
- **InputSizeGuardrail** - Limit input size to prevent abuse
- **DangerousPatternsGuardrail** - SQL injection, command injection detection
- **RegexFilterGuardrail** - User-configurable regex filtering
- **LanguageRestrictionGuardrail** - Restrict to specific languages

### Prompt Injection & Jailbreak
- **PromptInjectionSignatureGuardrail** - Detect injection patterns
- **SystemPromptLeakGuardrail** - Prevent system prompt extraction
- **JailbreakPatternGuardrail** - Detect DAN and jailbreak attempts
- **RolePlayInjectionGuardrail** - Role-play manipulation detection
- **OverrideInstructionGuardrail** - Detect instruction override attempts
- **CrossContextManipulationGuardrail** - Context manipulation detection
- **LLMClassifierInjectionGuardrail** - ML-based injection detection

### Output Validation
- **OutputPIIRedactionGuardrail** - Redact PII from outputs
- **SecretLeakOutputGuardrail** - Prevent secret leakage
- **InternalDataLeakGuardrail** - Detect internal data in outputs
- **ConfidentialityGuardrail** - Check for confidential markers
- **OutputSchemaValidationGuardrail** - Validate output structure
- **HallucinationRiskGuardrail** - Detect overconfident claims
- **CitationRequiredGuardrail** - Ensure factual claims have sources
- **CommandInjectionOutputGuardrail** - Prevent command injection in outputs

### Content Safety
- **NSFWContentGuardrail** - NSFW content detection
- **HateSpeechGuardrail** - Hate speech detection
- **ViolenceGuardrail** - Violent content detection
- **SelfHarmGuardrail** - Self-harm content detection with crisis resources
- **MedicalAdviceGuardrail** - Medical advice request detection

### Tool & Capability Control
- **ToolAccessControlGuardrail** - Whitelist/blacklist tools
- **DestructiveToolCallGuardrail** - Prevent destructive operations
- **RateLimitGuardrail** - Rate limit requests
- **CostThresholdGuardrail** - Monitor and limit costs

## Built-in Profiles

### `default`
Basic security and safety guardrails for general use.

### `enterprise_security`
Comprehensive security with strict PII/PHI protection, injection detection, and data leak prevention.

### `child_safety`
Maximum safety for children and educational contexts with NSFW blocking and tool restrictions.

### `healthcare`
HIPAA-compliant guardrails for healthcare applications.

### `financial`
Financial services compliance with strong PII protection.

### `minimal`
Minimal guardrails for development/testing.

## Advanced Usage

### Custom Guardrail Configuration

```python
from agnoguard import (
    GuardrailSuite,
    PIIDetectionGuardrailExtended,
    PromptInjectionSignatureGuardrail
)

custom_guardrails = [
    PIIDetectionGuardrailExtended(redact=True, severity="critical"),
    PromptInjectionSignatureGuardrail(),
]

suite = GuardrailSuite("default", custom_guardrails=custom_guardrails)
```

### Policy Builder

```python
from agnoguard.policy import PolicyBuilder
from agnoguard import PIIDetectionGuardrailExtended, SecretsInInputGuardrail

policy = (PolicyBuilder("my_policy")
    .add_input_guardrail(PIIDetectionGuardrailExtended(redact=True))
    .add_input_guardrail(SecretsInInputGuardrail())
)

team = policy.apply_to(team)
```

### Custom Regex Filters

```python
from agnoguard import RegexFilterGuardrail

patterns = [
    {"pattern": r"(?i)competitor_name", "name": "competitor", "action": "block"},
    {"pattern": r"internal_project_\w+", "name": "internal", "action": "block"}
]

regex_guard = RegexFilterGuardrail(patterns=patterns)
```

### Error Handling

```python
from agnoguard import GuardrailViolationError

try:
    response = team.run(user_input)
except GuardrailViolationError as e:
    print(f"Blocked: {e}")
    print(f"Details: {e.result.metadata}")
```

## Documentation

### GuardrailResult

Each guardrail returns a `GuardrailResult` with:
- `passed` (bool): Whether the check passed
- `action` (GuardrailAction): ALLOW, BLOCK, REDACT, WARN, MODIFY
- `severity` (GuardrailSeverity): INFO, WARNING, ERROR, CRITICAL
- `message` (str): Human-readable message
- `metadata` (dict): Additional details
- `modified_content` (str, optional): Redacted/modified content

### Context Support

Pass context to guardrails for advanced features:

```python
context = {
    "user_id": "user123",
    "session_id": "sess456",
    "user_role": "admin"
}

result = suite.check_input(content, context=context)
```

## Testing

```bash
pytest tests/
pytest --cov=agnoguard tests/
```

## Contributing

Contributions welcome! Please read our contributing guidelines.

## License

MIT License - see LICENSE file for details.

## Links

- Documentation: https://agnoguard.readthedocs.io
- GitHub: https://github.com/yourusername/agnoguard
- Issues: https://github.com/yourusername/agnoguard/issues

## Important Notes

- **Not a replacement for security reviews**: Use as defense-in-depth
- **Test thoroughly**: Validate guardrails in your specific context
- **Performance**: Some guardrails (ML-based) have higher latency
- **False positives**: Tune thresholds based on your use case

---

Made with ❤️ for safer LLM applications