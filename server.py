"""
Reach ASP — HTTP server (FastAPI).

Endpoints:
  POST /research        {question}          -> full cited, EIP-191 signed report; TEE-attested when 0G verifies it (JSON)
  POST /research/stream {question}          -> Server-Sent Events: live tool calls, then the report
  POST /read            {url}               -> read any page (stealth), quick primitive
  POST /search          {query, num?}       -> open-web search, quick primitive
  POST /receipt/verify  {signer,message_sha256,signature} -> {valid}
  GET  /health

x402 pay-per-call wraps the paid routes in production (same pattern as Aletheia's okxpay);
here the core engine is exposed directly so it can be tested and demoed.
"""
from __future__ import annotations
import json
import os
import queue
import threading

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

# load env from verity/.env if present
_envp = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "verity", ".env"))
if os.path.exists(_envp):
    for _l in open(_envp, encoding="utf-8", errors="replace"):
        _l = _l.strip()
        if "=" in _l and not _l.startswith("#"):
            _k, _v = _l.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip())

from reach.agent import deep_research  # noqa: E402
from reach.fable import MODEL_CHAIN  # noqa: E402
from landing import landing_html  # noqa: E402
from reach.sign import signer_address, verify_report_full  # noqa: E402
from reach.tools import SourceBook, _relevance, read_url, web_search  # noqa: E402

app = FastAPI(title="Reach ASP", version="1.0")


async def _body(req: Request) -> dict:
    """Parse the JSON body, degrading to {} on malformed/empty input so a bad request becomes a clean
    400 from the field checks below — never an unhandled 500."""
    try:
        b = await req.json()
        return b if isinstance(b, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


# The base URL is what a reviewer, a judge, or anyone following the marketplace listing opens first.
# Every paid endpoint is a POST, so a plain browser GET used to get a bare 404 — which reads as a dead
# service. This is a free, unmetered page: it advertises the paid routes, it is not one of them.
@app.get("/", response_class=HTMLResponse)
def index():
    return HTMLResponse(landing_html(signer_address(), MODEL_CHAIN))


# The judge-facing page. Served from the ASP's OWN domain so it can never point at a host or an agent id
# that has moved on — the previous hand-written deck cited a registration that had since been REJECTED.
# Regenerate with `python scripts/make_proof_deck.py` from the repo root; the file is data, not prose.
@app.get("/proof", response_class=HTMLResponse)
def proof():
    f = os.path.join(os.path.dirname(os.path.abspath(__file__)), "proof.html")
    if not os.path.exists(f):
        return HTMLResponse("<h1>Proof deck not generated</h1>", status_code=404)
    with open(f, encoding="utf-8") as fh:
        return HTMLResponse(fh.read())


@app.get("/health")
def health():
    return {"ok": True, "service": "reach", "model": os.environ.get("REACH_MODEL", "claude-fable-5"),
            "signer_address": signer_address()}


# The trust anchor for every report Reach signs. Without a published address there is nothing for a
# consumer to compare a recovered signer against, so the signature proves the report was signed by
# somebody — which is not the claim anyone cares about.
@app.get("/.well-known/reach-signer")
def well_known_signer():
    addr = signer_address()
    return {
        "service": "reach",
        "scheme": "EIP-191/personal_sign over sha256(canonical_json)",
        "signer_address": addr,
        "configured": addr is not None,
        "usage": "Recover the signer from signed.signature over signed.message_sha256 and require "
                 "it to equal this address. A report recovering to any other address was not "
                 "issued by Reach.",
    }


def _usage(endpoint: str, fee: float, what: str, example: dict, required: list) -> dict:
    """Reply to a paid request that supplied no input: the contract, with a request that would work.

    Shaped so it cannot read as a result — ok is false and there is no content/results key."""
    return {
        "ok": False,
        "status": "no_input_supplied",
        "endpoint": endpoint,
        "fee_usdt": fee,
        "message": "No input was supplied, so nothing was fetched. Send the body shown below. "
                   "Nothing was computed for this call.",
        "what_it_does": what,
        "required": required,
        "example_request": example,
    }


@app.post("/research")
async def research(req: Request):
    body = await _body(req)
    q = (body.get("question") or body.get("query") or "").strip()
    if not q:
        return JSONResponse(_usage(
            "/research", 0.05,
            "Answers one research question by actually searching and reading the live web, then "
            "returns a cited report where every claim links to a source it read, EIP-191 signed.",
            {"question": "Is X Layer an Ethereum L2, and what secures it?", "max_rounds": 12},
            ["question"],
        ), status_code=200)
    rounds = max(1, min(int(body.get("max_rounds", 12)), 16))
    # run the blocking research off the event loop so one deep run never freezes other requests
    res = await run_in_threadpool(deep_research, q, max_rounds=rounds)
    return JSONResponse(res)


@app.post("/research/stream")
async def research_stream(req: Request):
    body = await _body(req)
    q = (body.get("question") or body.get("query") or "").strip()
    if not q:
        return JSONResponse({"error": "missing 'question'"}, status_code=400)

    evq: "queue.Queue[dict|None]" = queue.Queue()

    def on_event(kind, data):
        evq.put({"event": kind, **data})

    def work():
        try:
            res = deep_research(q, max_rounds=max(1, min(int(body.get("max_rounds", 12)), 16)), on_event=on_event)
            evq.put({"event": "done", "result": res})
        except Exception as e:  # noqa: BLE001
            evq.put({"event": "error", "message": f"{type(e).__name__}: {e}"})
        finally:
            evq.put(None)

    threading.Thread(target=work, daemon=True).start()

    def stream():
        while True:
            item = evq.get()
            if item is None:
                break
            yield f"data: {json.dumps(item, ensure_ascii=False)}\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream")


# read_url / web_search report trouble in-band, as a prefix on the returned string, because they are
# written to be called BY THE MODEL inside the agent loop — where a readable sentence is more useful
# than an exception. At the HTTP boundary that convention has to be converted back into an explicit
# status, or the caller cannot tell a page from an apology.
_READ_FAILURE_MARKERS = (
    "ERROR reaching page:",
    "ERROR: read_url needs",
    "ERROR: blocked URL",
    "little readable text",
)
_SEARCH_FAILURE_MARKERS = (
    "No results",
    "no results",
    "ERROR",
    "search unavailable",
)


def _looks_like_failure(text: str) -> bool:
    t = (text or "").strip()
    if not t:
        return True
    return any(m in t for m in _SEARCH_FAILURE_MARKERS)


def _classify_read(text: str) -> tuple[bool, str | None]:
    """(retrieved, reason). A read counts as retrieved only if real page text came back."""
    t = (text or "").strip()
    if not t:
        return False, "the fetch returned nothing"
    for marker in _READ_FAILURE_MARKERS:
        if marker in t:
            if "blocked URL" in t:
                # The SSRF guard raises for two different reasons and they are not the same answer:
                # a name that does not resolve is a bad URL, not a blocked one. Reporting "blocked"
                # for a typo'd host tells the caller the wrong thing to fix.
                if "DNS resolution failed" in t or "cannot resolve" in t.lower():
                    return False, "the host name does not resolve"
                return False, "the URL resolves to a private or internal address and was blocked"
            if "needs a full" in t:
                return False, "not a valid http(s) URL"
            if "little readable text" in t:
                return False, "the page was reached but had almost no readable text (login wall or media-only)"
            return False, "the page could not be fetched"
    # The success shape is "[source N] <url>\nTITLE: ...\n\n<body>" — require a body beyond the header.
    body = t.split("\n\n", 1)[1].strip() if "\n\n" in t else ""
    if len(body) < 40:
        return False, "the page yielded too little text to be usable"
    return True, None



@app.post("/read")
async def read(req: Request):
    body = await _body(req)
    url = (body.get("url") or "").strip()
    if not url:
        # Payment settles in the gateway before this handler runs, so a 400 here charges the caller and
        # hands them nothing. OKX's availability probe also sends an empty body — a listed ASP was made
        # to change exactly this during review (ShieldSuite eff7c6d). Give them the contract instead.
        return JSONResponse(_usage(
            "/read", 0.01,
            "Fetches one web page and returns its readable text, defeating anti-bot and JS-only pages.",
            {"url": "https://example.com/article", "max_chars": 8000},
            ["url"],
        ), status_code=200)
    # Server-side cap: the client cannot request an unbounded read (OOM guard). Clamp to [200, 8000]
    # chars regardless of the body value, and never 500 on a malformed max_chars.
    try:
        req_chars = int(body.get("max_chars", 8000))
    except (TypeError, ValueError):
        req_chars = 8000
    max_chars = max(200, min(req_chars, 8000))
    sb = SourceBook()
    text = await run_in_threadpool(read_url, sb, url, max_chars)
    # read_url signals failure in its RETURN STRING, not by raising — "ERROR reaching page: ...",
    # "ERROR: blocked URL", or a note that the page had almost no readable text. Wrapping any of those
    # in {"ok": true} told a paying caller the read had succeeded and handed them an error message as
    # the page content. An agent consuming this checks `ok`, sees true, and goes on to summarise the
    # error string as if it were the article.
    retrieved, reason = _classify_read(text)
    return JSONResponse({
        "ok": retrieved,
        "retrieved": retrieved,
        "reason": reason,
        "url": url,
        "content": text if retrieved else None,
        "detail": None if retrieved else text,
        "chars": len(text) if retrieved else 0,
        "sources": sb.as_list(),
    }, status_code=200)


@app.post("/search")
async def search(req: Request):
    body = await _body(req)
    q = (body.get("query") or "").strip()
    if not q:
        return JSONResponse(_usage(
            "/search", 0.01,
            "Searches the live open web and returns ranked results with their URLs.",
            {"query": "X Layer rollup architecture", "num": 8},
            ["query"],
        ), status_code=200)
    # Clamp num server-side (defensive; never 500 on malformed input).
    try:
        num = int(body.get("num", 8))
    except (TypeError, ValueError):
        num = 8
    num = max(1, min(num, 20))
    sb = SourceBook()
    text = await run_in_threadpool(web_search, sb, q, num)
    # As with /read: a search where every engine was unreachable or returned nothing must not come
    # back as ok:true with an explanation in the results field. `sources` is the ground truth — if
    # nothing was added to the SourceBook, nothing was found.
    found = sb.as_list()
    ok = bool(found) and not _looks_like_failure(text)
    # Results can come back in quantity and still be about something else entirely. A measured call
    # for "X Layer OKX rollup architecture" returned six pages about Twitter because the engine
    # latched onto the leading token "X" — and the envelope reported ok:true, result_count:6,
    # reason:null. A calling agent has no way to see that, so it cites all six. Relevance is now
    # measured against the query's discriminating terms and reported in the envelope, so a degraded
    # answer is machine-detectable rather than a confident false positive.
    relevance = _relevance(q, text) if ok else 0.0
    degraded = ok and relevance < 0.5
    return JSONResponse({
        "ok": ok,
        "query": q,
        "result_count": len(found),
        "results": text if ok else None,
        "relevance": round(relevance, 2),
        "degraded": degraded,
        "reason": ("no search engine returned results for this query" if not ok else
                   (f"results matched only {relevance:.0%} of the query's distinctive terms — they may "
                    f"not be about this subject; treat as unverified" if degraded else None)),
        "detail": None if ok else text,
        "sources": found,
    }, status_code=200)


@app.post("/receipt/verify")
async def receipt_verify(req: Request):
    """Verify a signed Reach report.

    Accepts either the whole `signed` block or its fields directly, plus the original `payload` when
    the caller wants the report body checked against the digest as well. The previous version took
    `signer` from the request and only confirmed the signature recovered to it — so a report signed
    with an attacker's key, naming the attacker's own address, came back `valid: true`.
    """
    body = await _body(req)
    signed = body.get("signed") if isinstance(body.get("signed"), dict) else body
    return JSONResponse(verify_report_full(
        message_sha256=str(signed.get("message_sha256") or ""),
        signature=str(signed.get("signature") or ""),
        signer=signed.get("signer"),
        payload=body.get("payload") if isinstance(body.get("payload"), dict) else None,
        expected_signer=body.get("expected_signer"),
    ))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.environ.get("REACH_BIND", "127.0.0.1"), port=int(os.environ.get("PORT", "8790")))
