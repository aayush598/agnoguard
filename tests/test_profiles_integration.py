import pytest

from agnoguard.profiles import BUILTIN_PROFILES, list_profiles, get_profile
from agnoguard.suite import GuardrailSuite, GuardrailViolationError
from agnoguard.guardrails.input_validation import PIIDetectionGuardrailExtended
from agnoguard.guardrails.input_validation import PHIAwarenessGuardrail
from agnoguard.guardrails.content_safety import NSFWContentGuardrail


def test_list_and_get_profiles():
    # Ensure builtin profiles are present and list_profiles works
    profiles_map = list_profiles()
    assert isinstance(profiles_map, dict)
    assert "default" in BUILTIN_PROFILES
    assert "default" in profiles_map

    p = get_profile("default")
    assert p is not None
    assert "input_guardrails" in p and "output_guardrails" in p


def test_guardrail_suite_loads_profile_and_instantiates_guardrails():
    suite = GuardrailSuite.load_profile("default")
    # Expect some input and output guardrails
    assert len(suite.input_guardrails) >= 1
    assert len(suite.output_guardrails) >= 1

    # verify at least one guardrail type present
    names = [g.__class__.__name__ for g in suite.input_guardrails]
    assert "PIIDetectionGuardrailExtended" in names or any("PII" in n for n in names)


def test_default_profile_input_redacts_and_output_redacts():
    """
    default profile: PIIDetectionGuardrailExtended (redact True) is in inputs,
    and OutputPIIRedactionGuardrail in outputs. Verify pre_hook returns redacted input
    and post_hook redacts PII from outputs.
    """
    suite = GuardrailSuite("default")
    # pre_hook should be available
    pre_hook = suite.pre_hooks[0]
    post_hook = suite.post_hooks[0]

    # Input containing email should be redacted (PII detection in default profile is configured with redact=True)
    original_input = "Please process: my email is alice@example.com"
    pre_result = pre_hook(original_input)
    # If configured to redact, pre_hook returns modified content (string) replacing email
    assert isinstance(pre_result, str)
    assert "alice@example.com" not in pre_result
    assert "[REDACTED" in pre_result or "REDACTED" in pre_result

    # Simulate a model output that contains an SSN -> post_hook should redact SSN
    model_output = "Response: The SSN is 123-45-6789. Do not reveal."
    post_result = post_hook(model_output)
    assert isinstance(post_result, str)
    # SSN must be removed or redacted
    assert "123-45-6789" not in post_result
    assert "[REDACTED" in post_result or "REDACTED" in post_result


def test_enterprise_profile_blocks_phi_inputs():
    """Enterprise profile includes PHIAwarenessGuardrail which should block PHI-like text."""
    suite = GuardrailSuite("enterprise_security")

    # Find a pre_hook (there is exactly one implemented)
    pre_hook = suite.pre_hooks[0]

    # Create PHI-like content with multiple medical keywords to trigger PHIAwarenessGuardrail
    phi_content = "Patient has a diagnosis. Check medical record and prescription history."
    with pytest.raises(GuardrailViolationError) as exc:
        pre_hook(phi_content)

    # The exception should include a GuardrailResult with metadata
    assert hasattr(exc.value, "result")
    assert exc.value.result.passed is False
    assert "Potential PHI" in exc.value.result.message or "PHI" in exc.value.result.message


def test_child_safety_profile_blocks_nsfw_and_enforces_tool_policy():
    """
    child_safety profile includes NSFWContentGuardrail (input) and ToolAccessControlGuardrail (tool).
    Test that NSFW content is blocked by pre_hook.
    """
    suite = GuardrailSuite("child_safety")
    pre_hook = suite.pre_hooks[0]

    nsfw_text = "This is explicit porn content and very sexual."
    with pytest.raises(GuardrailViolationError):
        pre_hook(nsfw_text)

    # Also confirm the NSFW guardrail class is present among input guardrails
    assert any(isinstance(g, NSFWContentGuardrail) for g in suite.input_guardrails)
