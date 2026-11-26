"""Runs the whole agent team with pydantic-ai's TestModel over the real MCP tool server."""

import os
from pathlib import Path

import pytest
from pydantic_ai.models.test import TestModel

from hackbot.agents import AgentSystem
from hackbot.agents import runtime as runtime_module
from hackbot.codex_cli import (
    CodexOutcome,
    CodexUsage,
    codex_cyber_access_args,
    codex_exec_args,
    codex_mcp_overrides,
    extract_mind_result,
)
from hackbot.config import AGENT_NAMES, AgentModelBinding, Config

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "sample.sarif"


@pytest.mark.asyncio
async def test_team_runs_over_mcp(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("HACKBOT_DATA_DIR", str(tmp_path))
    cfg = Config.load()
    events = []
    async with AgentSystem(cfg) as system:
        assert {"web_search", "load_sarif", "sarif_findings"} <= set(system.tool_names)
        with (
            system.orchestrator.override(model=TestModel(call_tools=[], custom_output_text="done")),
            system.tutor.override(model=TestModel(custom_output_text="tutor says hi")),
        ):
            out = await system.run("coordinate", on_event=events.append)
            tutor = await system.run("explain", agent="tutor")
    assert out.answer == "done"
    assert tutor.answer == "tutor says hi"
    kinds = {(s["agent"], s["kind"]) for s in out.steps}
    assert ("orchestrator", "agent") in kinds
    assert all(s["status"] == "done" for s in out.steps)
    assert any(e.kind == "step" for e in events)


def test_model_bindings_are_role_specific_and_secret_free(tmp_path, monkeypatch):
    config_file = tmp_path / "bindings.json"
    config_file.write_text(
        """{
          "version": 1,
          "bindings": {
            "orchestrator": {"model": "qwen3-4b", "base_url": "http://127.0.0.1:11434/v1", "api_key_env": "LOCAL_LLM_KEY"},
            "analyst": {"model": "foundation-sec-8b", "api_key_env": "ANALYST_KEY"}
          }
        }""",
        encoding="utf-8",
    )
    monkeypatch.setenv("HACKBOT_MODEL_BINDINGS_FILE", str(config_file))
    monkeypatch.setenv("LOCAL_LLM_KEY", "local-secret")
    monkeypatch.setenv("ANALYST_KEY", "analyst-secret")
    monkeypatch.setenv("OPENAI_API_KEY", "global-secret")
    monkeypatch.setenv("HACKBOT_TUTOR_MODEL", "qwen3.5-2b")
    monkeypatch.setenv("HACKBOT_DATA_DIR", str(tmp_path / "data"))

    cfg = Config.load()

    assert set(cfg.public_bindings()) == set(AGENT_NAMES)
    assert cfg.binding_for("orchestrator").model == "qwen3-4b"
    assert cfg.api_key_for("orchestrator") == "local-secret"
    assert cfg.binding_for("analyst").model == "foundation-sec-8b"
    assert cfg.binding_for("tutor").model == "qwen3.5-2b"
    serialized = str(cfg.public_bindings())
    assert "local-secret" not in serialized
    assert "analyst-secret" not in serialized
    assert "global-secret" not in serialized


def test_artex_profile_binding_uses_bridge_without_exposing_provider_key(tmp_path, monkeypatch):
    config_file = tmp_path / "bindings.json"
    config_file.write_text(
        """{
          "version": 2,
          "bindings": {
            "orchestrator": {
              "source": "artex",
              "profile_id": 7,
              "provider": "chatgpt-plan",
              "model": "gpt-6.1-sol"
            },
            "analyst": {
              "source": "artex",
              "profile_id": 9,
              "provider": "anthropic",
              "model": "claude-sonnet"
            }
          }
        }""",
        encoding="utf-8",
    )
    monkeypatch.setenv("HACKBOT_MODEL_BINDINGS_FILE", str(config_file))
    monkeypatch.setenv("HACKBOT_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("ARTEX_BASE_URL", "http://127.0.0.1:8787")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    cfg = Config.load()

    binding = cfg.binding_for("orchestrator")
    assert binding.source == "artex"
    assert binding.profile_id == 7
    assert binding.base_url == "http://127.0.0.1:8787/api/hackbot/llm/profiles/7/v1"
    assert cfg.ready_for("orchestrator") is True
    assert cfg.uses_artex() is True
    public = cfg.public_bindings()
    assert public["orchestrator"]["credential_source"] == "ghostia-profile"
    assert public["orchestrator"]["api_key_present"] is False
    cfg.artex_access_token = "short-lived-session"
    assert cfg.api_key_for("analyst") == "short-lived-session"
    assert "short-lived-session" not in str(cfg.public_bindings())


def test_codex_binding_toggles_personal_mind_per_agent_without_copying_secret(tmp_path, monkeypatch):
    codex_home = tmp_path / "codex"
    codex_home.mkdir()
    (codex_home / "config.toml").write_text(
        '[mcp_servers.mind]\ncommand = "node"\nenv = { MIND_KEY = "secret-must-stay-in-codex" }\n'
        '\n[mcp_servers.mind.env]\nMIND_KEY = "secret-must-stay-in-codex"\n'
        '\n[mcp_servers.mind.tools.read_url]\nenabled = true\n'
        '\n[mcp_servers.notes]\ncommand = "notes-mcp"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    root = tmp_path / "ghostrecon"
    (root / "mcp").mkdir(parents=True)
    (root / "mcp" / "ghostrecon-mcp.mjs").write_text("// fixture\n", encoding="utf-8")

    with_mind = AgentModelBinding(
        model="gpt-daybreak-blue-latest",
        source="codex-cli",
        mcp_servers=("codex:mind", "ghostrecon"),
    )
    without_mind = AgentModelBinding(
        model="gpt-daybreak-blue-latest",
        source="codex-cli",
        mcp_servers=(),
    )
    enabled = codex_mcp_overrides(with_mind, root)
    disabled = codex_mcp_overrides(without_mind, root)

    assert "mcp_servers.mind.enabled=true" in enabled
    assert "mcp_servers.notes.enabled=false" in enabled
    assert all("mind.env.enabled" not in value for value in enabled)
    assert all("mind.tools.read_url.enabled" not in value for value in enabled)
    assert "mcp_servers.mind.enabled=false" in disabled
    assert "secret-must-stay-in-codex" not in str(enabled)
    assert "secret-must-stay-in-codex" not in str(disabled)
    missing = AgentModelBinding(
        model="gpt-daybreak-blue-latest",
        source="codex-cli",
        mcp_servers=("codex:missing",),
    )
    with pytest.raises(RuntimeError, match="não está disponível"):
        codex_mcp_overrides(missing, root)


def test_codex_daybreak_alias_enables_explicit_cyber_access_program():
    assert codex_cyber_access_args("gpt-daybreak-blue-latest") == [
        "--cyber-access-program", "daybreak_blue",
    ]
    assert codex_cyber_access_args("gpt-daybreak-red-latest") == [
        "--cyber-access-program", "daybreak_red",
    ]
    assert codex_cyber_access_args("gpt-6.2-sol") == []


def test_codex_exec_args_do_not_mix_approve_for_me_with_explicit_sandbox(tmp_path, monkeypatch):
    codex_home = tmp_path / "codex"
    codex_home.mkdir()
    (codex_home / "config.toml").write_text("", encoding="utf-8")
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    binding = AgentModelBinding(model="gpt-daybreak-blue-latest", source="codex-cli")

    args = codex_exec_args(binding, tmp_path)

    assert "--approve-for-me" in args
    assert "--sandbox" not in args
    assert "--dangerously-bypass-approvals-and-sandbox" not in args
    assert args[args.index("--cyber-access-program") + 1] == "daybreak_blue"


def test_mind_result_is_extracted_normalized_and_redacted():
    answer = """Análise concluída.
GHOSTRECON_MIND_RESULT_START
{"schema_version":1,"status":"completed","summary":"ok","skills":["outra"],"findings":[{"skill":"outra","title":"teste","confidence":9,"evidence":"token=super-secret-value"}],"false_positives":[],"evidence":[],"next_actions":[]}
GHOSTRECON_MIND_RESULT_END
"""
    clean, result = extract_mind_result(answer, {
        "enabled": True,
        "skills": ["ywh-triage"],
        "target": "example.com",
    })

    assert clean == "Análise concluída."
    assert result["skills"] == ["ywh-triage"]
    assert result["target"] == "example.com"
    assert result["findings"][0]["skill"] == "ywh-triage"
    assert result["findings"][0]["confidence"] == 1.0
    assert "super-secret-value" not in str(result)


@pytest.mark.asyncio
async def test_primary_agent_bound_to_codex_cli_uses_cli_runtime(tmp_path, monkeypatch):
    config_file = tmp_path / "bindings.json"
    config_file.write_text(
        '{"bindings":{'
        '"orchestrator":{"source":"codex-cli","model":"gpt-daybreak-blue-latest","mcp_servers":[]},'
        '"researcher":{"source":"codex-cli","model":"gpt-daybreak-blue-latest","mcp_servers":[]}'
        '}}',
        encoding="utf-8",
    )
    monkeypatch.setenv("HACKBOT_MODEL_BINDINGS_FILE", str(config_file))
    monkeypatch.setenv("HACKBOT_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("GHOSTRECON_ROOT", str(tmp_path / "ghostrecon"))
    captured = []

    async def fake_codex(binding, prompt, **kwargs):
        captured.append({"binding": binding, "prompt": prompt, "kwargs": kwargs})
        is_orchestrator = kwargs["agent"] == "orchestrator"
        return CodexOutcome(
            answer="resposta via Codex CLI" if is_orchestrator else "evidência do pesquisador",
            usage=CodexUsage(input_tokens=12, output_tokens=4, requests=1, tool_calls=1),
            steps=[{"id": "codex-1", "kind": "mcp_tool_call", "title": "mind.search", "status": "done"}],
            seconds=0.25,
        )

    monkeypatch.setattr(runtime_module, "run_codex_cli", fake_codex)
    cfg = Config.load()
    async with AgentSystem(cfg) as system:
        outcome = await system.run("use o Mind", agent="orchestrator")

    assert outcome.answer == "resposta via Codex CLI"
    assert outcome.usage.input_tokens == 24
    assert outcome.usage.tool_calls == 2
    assert [call["kwargs"]["agent"] for call in captured] == ["researcher", "orchestrator"]
    assert all(call["binding"].source == "codex-cli" for call in captured)
    assert all(call["kwargs"]["root"] == tmp_path / "ghostrecon" for call in captured)
    assert "evidência do pesquisador" in captured[-1]["prompt"]
    assert any(step["title"] == "mind.search" for step in outcome.steps)
