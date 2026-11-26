"""Regression tests for provider errors exposed by the GHOSTRECON adapter."""

from ghostrecon_api import _provider_failure


class ProviderFailure(Exception):
    status_code = 502


def test_subscription_limit_is_reported_as_actionable_rate_limit():
    status, message = _provider_failure(
        ProviderFailure(
            "LLM profile request failed: The ChatGPT user has reached their "
            "Subscription Sharing usage limit."
        )
    )

    assert status == 429
    assert "Limite do perfil ChatGPT/Codex" in message
    assert "chave de API" in message


def test_interrupted_stream_is_reported_as_temporary_unavailability():
    status, message = _provider_failure(
        ProviderFailure("provider stream ended before a terminal event")
    )

    assert status == 503
    assert "encerrou o stream" in message

