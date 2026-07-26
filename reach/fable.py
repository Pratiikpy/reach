"""
Fable 5 client on the 0G Compute router — Anthropic Messages API + an agentic tool loop.

This is the brain. We hand Claude Fable 5 (the strongest model available, via 0G's
decentralized inference) a toolbox and a goal, and it decides ENTIRELY on its own which
tools to call, in what order, how many times, and when it has enough to answer. We just
run the loop: model -> tool_use -> we execute -> feed results back -> repeat.

0G exposes an Anthropic-compatible endpoint at /v1/messages and supports `verify_tee`
(a trusted-execution-environment attestation that the response really came from the
model, unmodified). We request it so the AI step itself is provable.
"""
from __future__ import annotations
import json
import os
import time
from typing import Callable

import requests

ZG_BASE = os.environ.get("ZG_BASE_URL", "https://router-api.0g.ai/v1")
MODEL = os.environ.get("REACH_MODEL", "claude-fable-5")

# Ordered fallback chain, best first. EVERY model here must speak the Anthropic `/v1/messages` shape
# AND support tool calling, because the agentic loop below is built on `tool_use` blocks — the router's
# OpenAI-format models would need a different client entirely.
#
# Why this exists: a paid /research returned `500 Internal Server Error` to a user who had already been
# charged, because the router answered `403 BALANCE_INSUFFICIENT` for claude-fable-5. Measured across
# the router's Anthropic-format models: the three Claude tiers are all balance-gated on this account
# while glm-5.2 and glm-5 serve normally. One unavailable model must never take a paid endpoint down,
# so the client walks the chain instead of failing at the first name.
#
# The chain deliberately spans BOTH of the router's API dialects. Restricting it to the five
# Anthropic-format models would leave the endpoint one balance change away from dead again, while the
# router also carries a dozen capable OpenAI-format models; `_post` adapts to whichever dialect the
# chosen model speaks (see _to_openai_* / _from_openai_response), so the whole catalogue is usable.
MODEL_CHAIN = [m.strip() for m in os.environ.get(
    "REACH_MODEL_CHAIN",
    # Ordered by what actually served a real tool-using run on this account, best first, so a failure
    # costs one fast 403 rather than a walk through models that cannot answer.
    f"{MODEL},glm-5.2,deepseek-v4-pro,qwen3.7-max,minimax-m3,hy3,glm-5",
).split(",") if m.strip()]

# Router replies that mean "this MODEL cannot serve you" rather than "this request was bad". Only these
# advance the chain — a genuine 400 from a malformed request would otherwise silently downgrade the
# model on every call and hide the real bug.
_MODEL_UNAVAILABLE = ("balance_insufficient", "insufficient", "not found", "no provider",
                      "unavailable", "unsupported model", "model_not_found", "quota")

# Which dialect each model speaks, read once from the router rather than hardcoded — the catalogue
# changes, and guessing wrong means every call to that model 404s.
_FORMATS: dict[str, list[str]] = {}
# Used only if the catalogue call itself fails: everything on this router that speaks Anthropic today.
_ANTHROPIC_FALLBACK = {"claude-fable-5", "claude-opus-4-8", "claude-sonnet-5", "glm-5", "glm-5.2"}


def _model_formats(api_key: str) -> dict[str, list[str]]:
    global _FORMATS
    if _FORMATS:
        return _FORMATS
    try:
        r = requests.get(f"{ZG_BASE}/models", headers={"Authorization": f"Bearer {api_key}"}, timeout=30)
        if r.status_code == 200:
            _FORMATS = {m["id"]: (m.get("supported_formats") or []) for m in r.json().get("data", [])}
    except Exception:  # noqa: BLE001
        pass
    return _FORMATS


def _speaks_anthropic(model: str, api_key: str) -> bool:
    fmts = _model_formats(api_key).get(model)
    if fmts is None:
        return model in _ANTHROPIC_FALLBACK
    return "anthropic" in fmts


def _to_openai_tools(tool_schemas: list[dict]) -> list[dict]:
    """Anthropic {name, description, input_schema} -> OpenAI {type:function, function:{...parameters}}."""
    return [{"type": "function",
             "function": {"name": t["name"],
                          "description": t.get("description", ""),
                          "parameters": t.get("input_schema") or {"type": "object", "properties": {}}}}
            for t in tool_schemas]


def _to_openai_messages(messages: list[dict]) -> list[dict]:
    """Translate the internal Anthropic-block conversation into OpenAI chat messages.

    The loop keeps ONE internal representation (Anthropic blocks) and adapts at the edge, so the
    agentic logic does not fork per dialect. Three shapes have to cross over: assistant text,
    assistant tool_use (-> tool_calls), and user tool_result (-> role:"tool" messages).
    """
    out: list[dict] = []
    for m in messages:
        content = m.get("content")
        if isinstance(content, str):
            out.append({"role": m["role"], "content": content})
            continue
        blocks = content or []
        if m["role"] == "assistant":
            text = "\n".join(b.get("text", "") for b in blocks if b.get("type") == "text").strip()
            calls = [{"id": b.get("id"), "type": "function",
                      "function": {"name": b.get("name"),
                                   "arguments": json.dumps(b.get("input") or {})}}
                     for b in blocks if b.get("type") == "tool_use"]
            msg: dict = {"role": "assistant", "content": text or None}
            if calls:
                msg["tool_calls"] = calls
            out.append(msg)
            continue
        # A user turn carrying tool_result blocks becomes one OpenAI "tool" message per result.
        results = [b for b in blocks if b.get("type") == "tool_result"]
        if results:
            for b in results:
                out.append({"role": "tool", "tool_call_id": b.get("tool_use_id"),
                            "content": b.get("content") or ""})
        else:
            text = "\n".join(b.get("text", "") for b in blocks if b.get("type") == "text").strip()
            out.append({"role": "user", "content": text})
    return out


def _strip_reasoning(text: str) -> str:
    """Remove chain-of-thought wrappers some routed models emit inline.

    Measured: minimax-m3 begins its final answer with a literal `<think> The user wants me to ...`
    block. That is the model's scratchpad, not the report the caller paid for, and shipping it reads as
    a broken product. Models that return reasoning as a separate `thinking` block are already handled —
    only `text` blocks pass through here.
    """
    if not text:
        return ""
    for open_tag, close_tag in (("<think>", "</think>"), ("<thinking>", "</thinking>"),
                                ("<reasoning>", "</reasoning>")):
        while open_tag in text:
            head, _, rest = text.partition(open_tag)
            _, closed, tail = rest.partition(close_tag)
            # An unterminated block means the model never left its scratchpad; drop the remainder
            # rather than pasting a half-finished thought into the report.
            text = head + (tail if closed else "")
    return text.strip()


def _from_openai_response(data: dict) -> dict:
    """OpenAI chat completion -> the Anthropic-shaped {content:[blocks], stop_reason} the loop expects."""
    choice = (data.get("choices") or [{}])[0]
    msg = choice.get("message") or {}
    blocks: list[dict] = []
    text = msg.get("content")
    if isinstance(text, list):  # some providers return content as parts
        text = "".join(p.get("text", "") for p in text if isinstance(p, dict))
    text = _strip_reasoning(text or "")
    if text:
        blocks.append({"type": "text", "text": text})
    for tc in msg.get("tool_calls") or []:
        fn = tc.get("function") or {}
        raw = fn.get("arguments")
        try:
            args = json.loads(raw) if isinstance(raw, str) else (raw or {})
        except Exception:  # noqa: BLE001
            args = {}  # a malformed arg blob must not kill the run; the tool reports the error
        blocks.append({"type": "tool_use", "id": tc.get("id"), "name": fn.get("name"), "input": args})
    finish = choice.get("finish_reason")
    stop = "tool_use" if any(b["type"] == "tool_use" for b in blocks) else (
        "end_turn" if finish == "stop" else finish or "end_turn")
    return {"content": blocks, "stop_reason": stop,
            "x_0g_trace": data.get("x_0g_trace") or data.get("trace") or {}}


class Fable:
    def __init__(self, api_key: str | None = None, model: str = MODEL):
        self.api_key = api_key or os.environ.get("ZG_COMPUTE_API_KEY", "")
        if not self.api_key:
            raise RuntimeError("ZG_COMPUTE_API_KEY not set")
        self.model = model
        self.tee_seen = False  # true only if a 0G provider actually returned a verified TEE attestation
        self.provenance: dict = {}  # real 0G provenance: provider node, request ids (settled on-chain)
        # Every model substitution actually made, so a report can state which model wrote it rather
        # than implying the configured one did.
        self.model_fallbacks: list[dict] = []

    def _absorb_trace(self, data: dict) -> None:
        """Pull 0G's real provenance from the response: which provider node served it,
        the request id (settled on-chain), and the honest tee_verified flag."""
        tr = data.get("x_0g_trace") or data.get("trace") or {}
        if tr.get("tee_verified"):
            self.tee_seen = True
        if tr.get("provider") and not self.provenance.get("provider"):
            self.provenance["provider"] = tr.get("provider")
        rid = tr.get("request_id")
        if rid:
            self.provenance.setdefault("request_ids", []).append(rid)

    def _post(self, body: dict, timeout: int = 180) -> dict:
        """POST one turn, walking MODEL_CHAIN when a model itself is unavailable.

        Two distinct failure kinds are handled differently on purpose:
          * transient (network blip, 5xx, timeout) -> retry the SAME model, backing off;
          * model unavailable (403 BALANCE_INSUFFICIENT, unknown model) -> move to the NEXT model
            immediately, because retrying a balance-gated model just burns the payment window.

        Once a model answers, `self.model` is pinned to it for the rest of the run so the conversation
        does not hop between models mid-loop.
        """
        # Start from the currently pinned model, then anything further down the chain.
        chain = [self.model] + [m for m in MODEL_CHAIN if m != self.model]
        last = None
        for model in chain:
            for attempt in range(3):
                try:
                    if _speaks_anthropic(model, self.api_key):
                        url = f"{ZG_BASE}/messages"
                        headers = {"Content-Type": "application/json", "x-api-key": self.api_key,
                                   "anthropic-version": "2023-06-01"}
                        payload = {**body, "model": model}
                    else:
                        url = f"{ZG_BASE}/chat/completions"
                        headers = {"Content-Type": "application/json",
                                   "Authorization": f"Bearer {self.api_key}"}
                        payload = {"model": model,
                                   "messages": _to_openai_messages(body.get("messages") or []),
                                   "max_tokens": body.get("max_tokens", 4096)}
                        if body.get("tools"):
                            payload["tools"] = _to_openai_tools(body["tools"])
                        if body.get("verify_tee"):
                            payload["verify_tee"] = True
                    r = requests.post(url, headers=headers, json=payload, timeout=timeout)
                    if r.status_code == 200:
                        if model != self.model:
                            self.model_fallbacks.append({"from": self.model, "to": model,
                                                         "reason": str(last)[:160]})
                            self.model = model  # pin the working model for the remaining rounds
                        data = r.json()
                        return data if _speaks_anthropic(model, self.api_key) else _from_openai_response(data)
                    last = f"HTTP {r.status_code}: {r.text[:200]}"
                    blob = f"{r.status_code} {r.text[:300]}".lower()
                    if any(s in blob for s in _MODEL_UNAVAILABLE):
                        break  # this model cannot serve — do not waste retries on it
                    if r.status_code < 500 and r.status_code != 429:
                        break  # a real client error: the next model would reject it identically
                except Exception as e:  # noqa: BLE001
                    last = f"{type(e).__name__}: {e}"
                time.sleep(1.5 * (attempt + 1))
        raise RuntimeError(f"0G router call failed on every model {chain}: {last}")

    def _ensure_report(self, final: str, messages: list[dict], max_tokens: int) -> str:
        """Never return an empty report from a PAID call.

        Measured: one routed model finished its tool loop and returned zero text blocks — the caller
        would have paid and received an empty report. A model that stops without writing is asked once,
        explicitly, to write it; if it still returns nothing the model is dropped from the chain and the
        next one writes the report from the same gathered evidence.
        """
        if final.strip():
            return final
        ask = list(messages) + [{"role": "user", "content":
                                 "You returned no report. Write the FULL final report NOW, in prose, "
                                 "using the evidence already gathered above. Do not call any more tools."}]
        for _ in range(len(MODEL_CHAIN)):
            try:
                data = self._post({"model": self.model, "max_tokens": max_tokens, "messages": ask})
            except Exception:  # noqa: BLE001
                break
            out = "\n".join(b.get("text", "") for b in data.get("content", [])
                            if b.get("type") == "text").strip()
            if out:
                return out
            # This model will not write. Drop it and let _post pin the next one that answers.
            nxt = next((m for m in MODEL_CHAIN if m != self.model), None)
            if not nxt:
                break
            self.model_fallbacks.append({"from": self.model, "to": nxt,
                                         "reason": "returned an empty report"})
            self.model = nxt
        return final

    def run_agentic(
        self,
        system: str,
        user: str,
        tool_schemas: list[dict],
        dispatch: dict[str, Callable[..., str]],
        *,
        max_rounds: int = 14,
        max_tokens: int = 4096,
        deadline_s: float | None = None,
        on_event: Callable[[str, dict], None] | None = None,
    ) -> dict:
        """Run the full agentic loop. Fable decides every tool call. Returns
        {final_text, rounds, tool_calls:[...], stopped_reason}.

        deadline_s caps total wall-clock time: once it is exceeded the loop stops gathering and the
        model is asked to write its final report with what it has, so a paid call never runs past the
        x402 timeout window (a deep run with slow stealth reads could otherwise exceed it)."""
        # 0G's Fable-5 endpoint rejects the top-level `system` param, so we fold the
        # system instructions into the opening user turn (same effect, accepted shape).
        opening = f"{system}\n\n---\n\nRESEARCH REQUEST:\n{user}"
        messages: list[dict] = [{"role": "user", "content": opening}]
        tool_calls: list[dict] = []
        rounds = 0
        start = time.time()

        for rounds in range(1, max_rounds + 1):
            if deadline_s is not None and (time.time() - start) > deadline_s:
                break  # out of time — fall through and write the final report with what we have
            body = {
                "model": self.model,
                "max_tokens": max_tokens,
                "messages": messages,
                "tools": tool_schemas,
                "verify_tee": True,
            }
            data = self._post(body)
            self._absorb_trace(data)

            content = data.get("content", [])
            stop = data.get("stop_reason")
            # record assistant turn verbatim (needed so tool_result blocks line up)
            messages.append({"role": "assistant", "content": content})

            tool_uses = [b for b in content if b.get("type") == "tool_use"]
            if on_event:
                txt = " ".join(b.get("text", "") for b in content if b.get("type") == "text")
                on_event("assistant", {"round": rounds, "text": txt[:300],
                                        "tools": [t.get("name") for t in tool_uses]})

            if stop != "tool_use" or not tool_uses:
                final = "\n".join(b.get("text", "") for b in content if b.get("type") == "text").strip()
                final = self._ensure_report(final, messages, max_tokens)
                return {"final_text": final, "rounds": rounds, "tool_calls": tool_calls,
                        "stopped_reason": stop or "end"}

            # execute every tool the model asked for, feed results back
            results = []
            for tu in tool_uses:
                name, args, tid = tu.get("name"), tu.get("input", {}) or {}, tu.get("id")
                # Enforce the deadline INSIDE the loop, not only between rounds. A round that asks
                # for several slow tools can otherwise run far past the budget on its own — which is
                # how a paid /research overran its advertised x402 window and returned a gateway
                # 502 instead of the report. Remaining tools are skipped with an explicit note so
                # the model knows the gathering stopped rather than silently returning nothing.
                if deadline_s is not None and (time.time() - start) > deadline_s:
                    results.append({"type": "tool_result", "tool_use_id": tid,
                                    "content": "SKIPPED: research time budget reached. "
                                               "Write the final report from what has already been gathered."})
                    continue
                if on_event:
                    on_event("tool", {"round": rounds, "name": name, "args": args})
                fn = dispatch.get(name)
                try:
                    out = fn(**args) if fn else f"ERROR: unknown tool '{name}'"
                except TypeError as e:
                    out = f"ERROR calling {name}: bad arguments ({e})"
                except Exception as e:  # noqa: BLE001
                    out = f"ERROR in {name}: {type(e).__name__}: {str(e)[:160]}"
                tool_calls.append({"round": rounds, "name": name, "args": args, "chars": len(out or "")})
                results.append({"type": "tool_result", "tool_use_id": tid,
                                "content": (out or "")[:12000]})
            messages.append({"role": "user", "content": results})

        # ran out of rounds — ask for a final answer with what it has
        messages.append({"role": "user", "content":
                         "You have reached the research budget. Write your FINAL report now using everything gathered."})
        data = self._post({"model": self.model, "max_tokens": max_tokens, "messages": messages})
        final = "\n".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text").strip()
        final = self._ensure_report(final, messages, max_tokens)
        return {"final_text": final, "rounds": rounds, "tool_calls": tool_calls, "stopped_reason": "budget"}

    def complete(self, system: str, user: str, max_tokens: int = 2000) -> str:
        """Single non-tool completion (used for the final structuring pass)."""
        data = self._post({"model": self.model, "max_tokens": max_tokens,
                           "messages": [{"role": "user", "content": f"{system}\n\n---\n\n{user}"}],
                           "verify_tee": True})
        self._absorb_trace(data)
        return "\n".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text").strip()
