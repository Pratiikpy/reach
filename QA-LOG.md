
## Loop 27 — the silent field drop, put to the other four

Defect 19 was found on Horos. The same question to the rest: does an unrecognised field get dropped
in silence there too?

**All four do.** None warned. But "ignored" only matters if the answer changed, so that was measured
rather than assumed:

| service | asked for | received | with a typo'd key |
|---|---|---|---|
| Reach `/read` | 120 chars | 279 | **8,079 — twenty-nine times more** |
| Episteme `text.summarize` | 15 words | 11 | 21 — 40% over the cap |

Both materially change what the buyer gets. Reach's is the sharpest: a caller sizing a context window
asks for 120 characters and silently receives 8 KB.

### Fixed on Reach

`/read`, `/search` and `/research` now return `ignored_input` naming each unread field, suggesting the
closest accepted one and listing the full set. Verified live — the typo'd request still returns 8,079
characters but now says why, and a correct request returns 279 with no note.

`/research` accepts both `question` and `query`, and neither is flagged.

### Deliberately not done in the same loop

Doxa, Episteme and Aletheia share the defect and are **not** fixed here. Each needs its accepted-field
set derived from a different place — Episteme from its node schemas, Doxa from `input_contract()`,
Aletheia from per-route reads — and bundling four codebases into one change would make a bad failure
hard to attribute. They are recorded, with the harm on Episteme already quantified, and taken one at
a time.

Two of five done: Horos warns inside its signed envelope, Reach in `ignored_input`.

## Loop 31 — auditing loop 30, and a regression sweep that caught me

### The loop-30 middleware, attacked

It added a `clone()` of the request body — the exact construct behind loop 14's 32 KB cliff — and it
rewrites responses, which could break streaming. Both tested rather than reasoned about:

| check | result |
|---|---|
| 400 KB body through the new clone | `200` — safe, because Aletheia serves in-process with no proxy re-reading the body |
| the 402 challenge | untouched, no injected field, header intact |
| Reach SSE after two loops of gateway edits | `text/event-stream`, 6 events, streaming intact |
| a guarded JSON route with a typo | annotated, answer still present |

**A false finding avoided:** `/research/stream` returned 404 on Aletheia and briefly looked like a
broken listed route. It is **Reach's** endpoint, not Aletheia's — the 404 is correct. Checked before
writing it down.

### Regression sweep after thirty loops: five flags, one real

| flag | verdict |
|---|---|
| Doxa `audit.diff` 402 | wallet 1 at `0.008`, below the `$0.02` price — drained wallet |
| Aletheia `Proof-of-Work` 402 | same wallet, same cause |
| Episteme `receipt.verify` nulls | known auditor false positive: `expected_public_key` is *correctly* null when no key is pinned |
| **Reach `/read` and `/search` nulls** | **real, and mine** |

The last one was caused by loop 27's own fix: `ignored_input` was emitted on every response, null
when the request was fine. That is noise every caller has to filter, and it makes "no notice"
indistinguishable from "a notice that came back empty". The field is now omitted when there is
nothing to say — verified live: absent on a correct call, present with the suggestion on a typo.

**The sweep flagged a field that a fix had introduced two loops earlier, and the sweep was right.**
That is the whole argument for re-running the broad check after narrow changes: nothing in loop 27's
own tests could have caught it, because the defect was in what the fix added, not in what it fixed.
