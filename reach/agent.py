"""
Reach Deep Research — the orchestrator.

One question in → a cited, provable research report out. Claude Fable 5 runs the whole
investigation autonomously: it decides how to decompose the question, which corners of the
internet to reach (open web + Twitter + Reddit + YouTube + GitHub), how deep to read, when
to cross-check, and when it has enough. Every claim is cited to a source it actually touched;
the AI step is TEE-attested when the 0G provider returns a verified attestation (tee_verified reflects
this and is often false on the standard router); each report carries an EIP-191 signature.

Not a fixed pipeline — the model owns the flow. That's what lets it research ANYTHING.
"""
from __future__ import annotations
import datetime
import hashlib
import re
from typing import Callable

from .fable import Fable
from .sign import sign_report
from .tools import SourceBook, build_toolset

SYSTEM = """You are Reach — an elite autonomous research agent with live internet access: open-web search plus a stealth page reader that defeats anti-bot / JavaScript blocks, and — when they appear in your tool list — walled-garden and developer channels (social, video transcripts, code search).

Your job: answer the user's research request as thoroughly and honestly as a top human analyst who had a full day to dig — but in one run. You decide the entire approach. There is no fixed script.

How to work well:
- DECOMPOSE the request into the specific things you need to find out (facts, evidence for, evidence against, context, primary voices, red flags).
- REACH WIDELY. Use web_search from several angles. Use read_url to actually read the best sources in depth, not just snippets. If additional channels appear in your tools (social, video transcripts, code search), use them when human opinion, sentiment, primary voices, or source code matter — that is signal ordinary tools miss. Use ONLY the tools you are actually given; never assume a channel you don't have.
- CROSS-CHECK. Prefer claims backed by more than one independent source. Note when something is single-source or contested.
- GO DEEPER when you find gaps or conflicts — search and read again. Don't stop at the first pass.
- BE HONEST. Never invent facts, numbers, dates, quotes, or sources. If the evidence is thin or mixed, say so plainly. Distinguish fact from speculation.

When you have enough, STOP calling tools and write the FINAL REPORT in this exact structure (markdown):

## Answer
2–5 sentences: the direct, bottom-line answer to what they asked.

## Key findings
- 5–10 bullet points. EVERY factual bullet MUST end with a citation like [3] or [3][7] referring to the sources you read. Mark a bullet "(single-source)" if only one source supports it.

## What the evidence says
2–4 short paragraphs synthesizing the picture, including any disagreement between sources or between web vs. social sentiment. Cite inline with [n].

## Caveats & what to verify
- 2–4 bullets: what is uncertain, what you couldn't confirm, what the reader should check themselves.

## Confidence
One line: HIGH / MEDIUM / LOW + one clause why.

Rules for citations: only cite source numbers that appeared in your tool results. Do not fabricate a source or a number. If you never found solid evidence for a claim, drop the claim rather than inventing a citation."""


def _used_citation_numbers(text: str) -> set[int]:
    return {int(x) for x in re.findall(r"\[(\d+)\]", text or "")}


def deep_research(
    question: str,
    *,
    api_key: str | None = None,
    max_rounds: int = 12,
    # 150s of gathering, not 210. The deadline caps GATHERING only; the model then still has to
    # write the final report, which measured ~60s. At 210 the total came in at 270s against a 290s
    # gateway cap and a 300s advertised window — a slow write-up would have overrun it and returned
    # a 502 to someone who had already paid. 150 + ~60 leaves real headroom.
    deadline_s: float = 150.0,
    on_event: Callable[[str, dict], None] | None = None,
) -> dict:
    observed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    sb = SourceBook()
    schemas, dispatch = build_toolset(sb)
    fable = Fable(api_key=api_key)

    # deadline_s keeps the whole run inside the x402 payment window (300s): it gathers until the
    # deadline, then writes its report with what it has — a paid call never times out.
    result = fable.run_agentic(
        SYSTEM, question.strip(), schemas, dispatch,
        max_rounds=max_rounds, deadline_s=deadline_s, on_event=on_event,
    )
    report = result["final_text"]

    # attach only the sources the report actually cites, plus keep the full touched list
    all_sources = sb.as_list()
    cited_nums = _used_citation_numbers(report)
    cited = [s for s in all_sources if s["n"] in cited_nums]

    payload = {
        "kind": "reach_deep_research",
        "question": question.strip()[:500],
        "report_sha256": hashlib.sha256(report.encode("utf-8")).hexdigest(),  # covers the WHOLE report (tamper-evident)
        "answer_sha_excerpt": report[:600],
        "cited_source_urls": [s["url"] for s in cited],
        "tee_verified": bool(fable.tee_seen),
        "og_provider": fable.provenance.get("provider"),
        "observed_at": observed_at,
    }
    signed = sign_report(payload)

    return {
        "ok": True,
        "observed_at": observed_at,
        "question": question.strip(),
        "report": report,
        "sources": all_sources,
        "cited_sources": cited,
        "rounds": result["rounds"],
        "tool_calls": result["tool_calls"],
        "tools_used": sorted({t["name"] for t in result["tool_calls"]}),
        "reaches": sorted({s["via"] for s in all_sources if s.get("via")}),
        "tee_verified": bool(fable.tee_seen),
        "og_provenance": fable.provenance,
        "signed": signed,
        # `model` is the model that ACTUALLY served the run, not the configured one: the client walks a
        # fallback chain when a model is balance-gated, and a report naming a model that never ran
        # would be a false provenance claim. `model_fallbacks` records any substitution.
        "model": fable.model,
        "model_fallbacks": fable.model_fallbacks,
        "disclaimer": "Autonomous multi-source research. Every claim cites a source Reach actually read; verify the caveats yourself. Not financial advice.",
    }
