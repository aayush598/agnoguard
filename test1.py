import asyncio

from agno.team import Team
from agno.agent import Agent
from agno.models.google import Gemini

from agnoguard import GuardrailSuite, PIIDetectionGuardrailExtended
from agnoguard import GuardrailViolationError

from dotenv import load_dotenv
load_dotenv()


async def main():
    """Demonstrate PII detection guardrails using AgnoGuard."""
    print("🛡️ PII Detection Guardrails Demo (AgnoGuard Version)")
    print("=" * 60)

    # -------------------------------------------------------------
    # Team 1: uses the DEFAULT security profile (includes PII rules)
    # -------------------------------------------------------------
    suite = GuardrailSuite("default")

    team = Team(
        name="Privacy-Protected Team",
        model=Gemini(id="gemini-2.5-flash-lite"),
        members=[Agent(name="Assistant", role="Customer service assistant")],
        pre_hooks=suite.pre_hooks,
        description="Team with default AgnoGuard input protection.",
        instructions="You are a helpful customer service assistant. Protect privacy."
    )

    # Helper function to test guardrails
    def test_request(label, text):
        print(f"\n🔍 {label}")
        print("-" * 50)
        try:
            team.print_response(input=text)
            print("✅ Processed successfully (no violation)")
        except GuardrailViolationError as e:
            print(f"❌ Blocked by guardrail: {e}")
            print(f"   Details: {e.result.metadata}")

    # -------------------------
    # RUN TEST CASES
    # -------------------------

    # Test 1: No PII
    test_request(
        "Test 1: Normal request (no PII)",
        "Can you help me understand your return policy?"
    )

    # Test 2–7: PII inputs expected to be blocked
    test_request(
        "Test 2: SSN",
        "Hi, my Social Security Number is 123-45-6789. Can you help me with my account?"
    )

    test_request(
        "Test 3: Credit Card",
        "I'd like to update my payment method. My new card number is 4532 1234 5678 9012."
    )

    test_request(
        "Test 4: Email Address",
        "Please send the receipt to john.doe@example.com for my recent purchase."
    )

    test_request(
        "Test 5: Phone Number",
        "My phone number is 555-123-4567. Please call me about my order."
    )

    test_request(
        "Test 6: Multiple PII",
        "Hi, I'm John Smith. My email is john@company.com and my phone is 555.987.6543."
    )

    test_request(
        "Test 7: Hidden credit card",
        "Can you verify my credit card ending in 4532123456789012?"
    )

    print("\n" + "=" * 60)
    print("🎯 PII Detection (Blocking) Complete")

    # -------------------------------------------------------------
    # Team 2: PII-masking instead of blocking
    # -------------------------------------------------------------
    print("\n🛡️ Masking Mode with PIIDetectionGuardrailExtended")
    print("=" * 60)

    masking_suite = GuardrailSuite(
        "default",
        custom_guardrails=[PIIDetectionGuardrailExtended(redact=True)]
    )

    masked_team = Team(
        name="PII-Masked Team",
        model=Gemini(id="gemini-2.5-flash-lite"),
        members=[Agent(name="Assistant", role="Customer service assistant")],
        pre_hooks=masking_suite.pre_hooks,
        description="Team with PII masking enabled.",
        instructions="Mask personal info before processing."
    )

    print("\n🔍 Test 8: Masking SSN Input")
    print("-" * 50)
    masked_team.print_response(
        input="Hi, my Social Security Number is 123-45-6789. Can you help me with my account?"
    )


if __name__ == "__main__":
    asyncio.run(main())
