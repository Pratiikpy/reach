"""The channel tier contract.

The bug these pin down: github_search and twitter_thread were gated behind the `gh` and `twitter`
CLIs, which only exist on a developer laptop. In production the model was never offered them, so
Reach quietly had less reach than it claimed. These tests assert the keyless channels are always
offered, and that the session-backed ones are offered only when a session actually exists.

Network-touching assertions are marked so the suite stays useful offline.
"""
from __future__ import annotations

import os

import pytest

from reach.tools import (SourceBook, build_toolset, hn_search, reddit_search,
                         rss_read, twitter_search, twitter_thread)

KEYLESS = {"web_search", "read_url", "github_search", "hn_search", "twitter_thread", "rss_read"}


def _names(monkeypatch=None):
    schemas, dispatch = build_toolset(SourceBook())
    assert {s["name"] for s in schemas} == set(dispatch), "schema list and dispatch map disagree"
    return {s["name"] for s in schemas}


def test_keyless_channels_are_always_offered():
    """No CLI, no key, no cookie — these must still be there, on any host."""
    assert KEYLESS <= _names()


def test_session_channels_hidden_without_a_session(monkeypatch):
    for var in ("X_AUTH_TOKEN", "X_CT0", "REDDIT_COOKIE"):
        monkeypatch.delenv(var, raising=False)
    names = _names()
    assert "twitter_search" not in names
    assert "reddit_search" not in names


def test_session_channels_appear_when_configured(monkeypatch):
    monkeypatch.setenv("X_AUTH_TOKEN", "dummy")
    monkeypatch.setenv("X_CT0", "dummy")
    monkeypatch.setenv("REDDIT_COOKIE", "dummy=1")
    names = _names()
    assert "twitter_search" in names
    assert "reddit_search" in names


def test_unconfigured_session_tools_explain_themselves(monkeypatch):
    """They must say why they cannot run and name a working alternative — never return nothing and
    let the model conclude the topic is undiscussed."""
    for var in ("X_AUTH_TOKEN", "X_CT0", "REDDIT_COOKIE"):
        monkeypatch.delenv(var, raising=False)
    sb = SourceBook()
    t = twitter_search(sb, "x layer")
    r = reddit_search(sb, "x layer")
    for msg, alt in ((t, "web_search"), (r, "hn_search")):
        assert "not available" in msg
        assert alt in msg
    assert sb.as_list() == [], "a tool that could not run must not register sources"


def test_tweet_id_is_parsed_from_urls_and_rejects_junk():
    sb = SourceBook()
    assert "needs a tweet URL" in twitter_thread(sb, "not-a-tweet")
    assert "needs a tweet URL" in twitter_thread(sb, "")


@pytest.mark.parametrize("bad", ["http://127.0.0.1/feed.xml", "http://169.254.169.254/latest/meta-data/"])
def test_rss_read_is_ssrf_guarded(bad):
    """rss_read fetches an operator-supplied URL, so it goes through the same egress guard."""
    from reach.tools import SsrfError
    with pytest.raises(SsrfError):
        rss_read(SourceBook(), bad)


@pytest.mark.network
def test_twitter_thread_reads_a_real_public_tweet():
    """Tweet 20 is the first tweet ever posted and is not going anywhere.

    It is also a 2-digit id, which is why the parser anchors on `status/<id>` instead of assuming a
    modern 19-digit snowflake.
    """
    out = twitter_thread(SourceBook(), "https://x.com/jack/status/20")
    assert "@jack" in out
    assert "just setting up my twttr" in out


@pytest.mark.network
def test_hn_search_ranks_by_engagement():
    sb = SourceBook()
    out = hn_search(sb, "kubernetes")
    assert "Hacker News" in out
    pts = [int(p.replace(",", "")) for p in __import__("re").findall(r"\((\d[\d,]*) points", out)]
    assert pts == sorted(pts, reverse=True), f"results not ranked by points: {pts}"
    assert len(sb.as_list()) > 0
