"""Regression tests for provider errors exposed by the GHOSTRECON adapter."""

import ghostrecon_api

from ghostrecon_api import _provider_failure, _run_timeout_seconds


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


def test_run_timeout_defaults_to_thirty_minutes_and_is_bounded(monkeypatch):
    monkeypatch.delenv("GHOSTRECON_HACKBOT_RUN_TIMEOUT", raising=False)
    assert _run_timeout_seconds() == 1800

    monkeypatch.setenv("GHOSTRECON_HACKBOT_RUN_TIMEOUT", "7200")
    assert _run_timeout_seconds() == 7200

    monkeypatch.setenv("GHOSTRECON_HACKBOT_RUN_TIMEOUT", "99999")
    assert _run_timeout_seconds() == ghostrecon_api.MAX_RUN_TIMEOUT_SECONDS

    monkeypatch.setenv("GHOSTRECON_HACKBOT_RUN_TIMEOUT", "invalido")
    assert _run_timeout_seconds() == ghostrecon_api.DEFAULT_RUN_TIMEOUT_SECONDS

