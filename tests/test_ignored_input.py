"""A field this service does not read must be named, not dropped in silence.

Measured on the live service: `/read` asked for `max_chars: 120` returned 279 characters. The same
request with `max_charss` returned **8,079** — the caller capped their output, was ignored, and
received twenty-nine times as much. A caller sizing a context window acts on that number, and nothing
in the response said the cap had been discarded.

A note rather than a refusal: rejecting an unexpected field would break any client sending one today,
which is too high a price for catching a typo.
"""
from __future__ import annotations

import pytest

from server import _ACCEPTED_FIELDS, _ignored_note


def test_a_typo_is_named_with_a_suggestion():
    note = _ignored_note("/read", {"url": "https://example.com/", "max_charss": 120})
    assert note and "max_charss" in note
    assert "did you mean 'max_chars'" in note
    assert "may not be the one you intended" in note


def test_it_lists_what_the_route_does_read():
    note = _ignored_note("/search", {"query": "x", "limit": 5})
    assert note and "limit" in note
    assert "Accepted fields: num, query" in note


def test_a_correct_request_produces_no_note():
    assert _ignored_note("/read", {"url": "https://example.com/", "max_chars": 200}) is None
    assert _ignored_note("/search", {"query": "x", "num": 5}) is None


def test_both_accepted_spellings_of_the_question_are_fine():
    """/research reads `question` or `query`; neither is a mistake."""
    assert _ignored_note("/research", {"question": "x"}) is None
    assert _ignored_note("/research", {"query": "x"}) is None


def test_several_unknown_fields_are_all_named():
    note = _ignored_note("/read", {"url": "u", "aaa": 1, "bbb": 2})
    assert "aaa" in note and "bbb" in note and "them:" in note


def test_an_unguarded_route_is_left_alone():
    assert _ignored_note("/receipt/verify", {"anything": 1}) is None


def test_a_non_dict_body_does_not_raise():
    assert _ignored_note("/read", None) is None


@pytest.mark.parametrize("path", sorted(_ACCEPTED_FIELDS))
def test_every_guarded_route_declares_something(path):
    """An empty accepted-set would silently disable the check for that route."""
    assert _ACCEPTED_FIELDS[path], f"{path} declares no accepted fields"


def test_the_field_is_absent_when_there_is_nothing_to_report():
    """A null on every correct call is noise the caller has to filter, and it makes "no notice" look
    like "an empty notice". Found by a regression sweep flagging the null this fix had introduced."""
    from fastapi.testclient import TestClient

    import server as srv
    c = TestClient(srv.app)
    # A route that needs no network: an empty body returns the usage contract, not a result.
    r = c.post("/search", json={})
    assert "ignored_input" not in r.json()
