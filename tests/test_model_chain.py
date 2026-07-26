"""Regression tests for the model fallback chain and the report guarantees around it.

These exist because of a measured production failure: a PAID `/research` call returned
`500 Internal Server Error` to a caller who had already been charged, because the 0G router answered
`403 BALANCE_INSUFFICIENT` for the single configured model — while other models on the same key served
normally. The router gates availability per MODEL, not per account.

Three behaviours are pinned here, all of them things that were wrong at some point:

  * a gated model is skipped and the next one serves, so one gated model cannot take a paid endpoint
    down;
  * a malformed REQUEST is not retried against the whole chain — that would multiply the latency of a
    paid call and still fail;
  * reasoning scratchpads never reach the caller as the report (`minimax-m3` prefixed its answer with a
    literal `<think>` block).

Run: python -m pytest tests/ -q      (from the reach/ directory)
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("ZG_COMPUTE_API_KEY", "test-key-not-used-network-is-stubbed")

from reach import fable as F  # noqa: E402


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None, text: str = ""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


def _anthropic_ok(model: str) -> dict:
    return {"content": [{"type": "text", "text": f"answered by {model}"}], "stop_reason": "end_turn"}


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(F.time, "sleep", lambda *_: None)
    # Pin dialects so the test never depends on the live catalogue.
    monkeypatch.setattr(F, "_speaks_anthropic", lambda m, k: True)


def test_gated_model_falls_through_to_the_next(monkeypatch):
    tried: list[str] = []

    def fake_post(url, headers=None, json=None, timeout=None):
        model = json["model"]
        tried.append(model)
        if model == "claude-fable-5":
            return _FakeResponse(403, text='{"message":"BALANCE_INSUFFICIENT"}')
        return _FakeResponse(200, _anthropic_ok(model))

    monkeypatch.setattr(F.requests, "post", fake_post)
    f = F.Fable(model="claude-fable-5")
    data = f._post({"model": "claude-fable-5", "max_tokens": 32, "messages": []})

    assert data["content"][0]["text"] != "answered by claude-fable-5"
    assert tried[0] == "claude-fable-5", "the preferred model must be tried first"
    assert f.model != "claude-fable-5", "the working model must be pinned for the rest of the run"
    assert f.model_fallbacks and f.model_fallbacks[0]["from"] == "claude-fable-5"
    # A gated model must cost exactly ONE attempt: retrying it just burns the payment window.
    assert tried.count("claude-fable-5") == 1


def test_bad_request_is_not_retried_across_every_model(monkeypatch):
    tried: list[str] = []

    def fake_post(url, headers=None, json=None, timeout=None):
        tried.append(json["model"])
        return _FakeResponse(400, text='{"error":"messages[0].content is invalid"}')

    monkeypatch.setattr(F.requests, "post", fake_post)
    with pytest.raises(RuntimeError):
        F.Fable(model="glm-5.2")._post({"model": "glm-5.2", "max_tokens": 32, "messages": []})
    # One shot per model, no retries — a malformed request fails identically everywhere.
    assert len(tried) == len(set(tried)), f"a bad request was retried on the same model: {tried}"


def test_transient_error_retries_the_same_model(monkeypatch):
    calls = {"n": 0}

    def fake_post(url, headers=None, json=None, timeout=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return _FakeResponse(503, text="upstream busy")
        return _FakeResponse(200, _anthropic_ok(json["model"]))

    monkeypatch.setattr(F.requests, "post", fake_post)
    f = F.Fable(model="glm-5.2")
    data = f._post({"model": "glm-5.2", "max_tokens": 32, "messages": []})
    assert data["content"][0]["text"] == "answered by glm-5.2"
    assert f.model == "glm-5.2", "a transient blip must not switch models"


@pytest.mark.parametrize("raw,expected", [
    ("<think> scratch </think>The report.", "The report."),
    ("<think>never closed and never answered", ""),
    ("A<thinking>mid</thinking>B", "AB"),
    ("plain report", "plain report"),
])
def test_reasoning_never_reaches_the_caller(raw, expected):
    assert F._strip_reasoning(raw) == expected


def test_openai_tool_roundtrip():
    """A tool call must survive translation into OpenAI shape and back."""
    oai = {"choices": [{"finish_reason": "tool_calls", "message": {
        "content": "", "tool_calls": [{"id": "c1", "type": "function",
                                       "function": {"name": "web_search",
                                                    "arguments": '{"query": "x layer"}'}}]}}]}
    back = F._from_openai_response(oai)
    assert back["stop_reason"] == "tool_use"
    block = back["content"][0]
    assert (block["type"], block["name"], block["input"]) == ("tool_use", "web_search", {"query": "x layer"})

    # And the reverse: an assistant tool_use turn plus its tool_result must convert to OpenAI messages.
    msgs = F._to_openai_messages([
        {"role": "assistant", "content": [{"type": "tool_use", "id": "c1", "name": "web_search",
                                           "input": {"query": "x"}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "c1", "content": "RESULT"}]},
    ])
    assert msgs[0]["tool_calls"][0]["function"]["name"] == "web_search"
    assert msgs[1] == {"role": "tool", "tool_call_id": "c1", "content": "RESULT"}


def test_malformed_tool_arguments_do_not_crash_the_run():
    """A provider emitting invalid JSON args must degrade to {}, not kill a paid research run."""
    oai = {"choices": [{"finish_reason": "tool_calls", "message": {
        "content": None, "tool_calls": [{"id": "c1", "type": "function",
                                         "function": {"name": "web_search", "arguments": "{not json"}}]}}]}
    assert F._from_openai_response(oai)["content"][0]["input"] == {}
