"""
Reach — the tool layer the research agent (Claude Fable 5) drives autonomously.

Each tool reaches a different part of the internet and returns clean, LLM-ready text
plus the source URLs it touched (so every claim in the final report can be cited).

A tool is only shown to the model when this host can actually perform it, so the agent never spends a
round on something that can only answer "unavailable", and a buyer is never charged for a reach we
cannot make. Three tiers:

  keyless (always present — public HTTP, nothing to configure, cannot expire)
      web_search      open web, engine chain DuckDuckGo -> Brave -> Bing, relevance-scored
      read_url        any page as clean text, stealth browser fallback for JS-only pages
      github_search   repositories by topic, stars, language        (api.github.com)
      hn_search       Hacker News stories AND comments, ranked      (hn.algolia.com)
      twitter_thread  one public X post in full                     (cdn.syndication.twimg.com)
      rss_read        any RSS/Atom feed

  binary-backed (present when the binary is installed)
      youtube         title, channel, description, transcript       (yt-dlp)

  session-backed (present only when an operator configured a session)
      twitter_search  live X search   — X publishes no keyless search endpoint
      reddit_search   Reddit threads  — Reddit answers 403 to unauthenticated datacenter reads

These tiers are not cosmetic. github_search and twitter_thread used to be gated behind the `gh` and
`twitter` CLIs, which exist on a developer laptop and not on the server — so in production the model
was never offered them at all. They now speak to public endpoints directly. The session tier stays
gated on purpose: a cookie cannot be renewed automatically, so a service that advertised it as a
standing capability would be selling something that silently dies.

Scrapling (BSD-3) provides the stealth fetch engine. Channel routing follows the approach taken by
agent-reach (MIT) — see THIRD_PARTY_LICENSES.md — reimplemented here over HTTP rather than over its
CLIs, because agent-reach extracts cookies from a local browser and a hosted service has none.
"""
from __future__ import annotations
import base64
import ipaddress
import json
import re
import shutil
import socket
import subprocess
import threading
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable

import requests

# ---- source registry: every URL a tool touches, deduped, for the citation graph ----


@dataclass
class SourceBook:
    """Collects sources across a research run so the final report can cite [n] -> url."""
    _sources: list[dict] = field(default_factory=list)
    _seen: dict[str, int] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def add(self, url: str, title: str = "", via: str = "") -> int:
        url = (url or "").strip()
        if not url:
            return 0
        with self._lock:
            if url in self._seen:
                return self._seen[url]
            n = len(self._sources) + 1
            self._sources.append({"n": n, "url": url, "title": (title or "")[:180], "via": via})
            self._seen[url] = n
            return n

    def as_list(self) -> list[dict]:
        return list(self._sources)


# ---- helpers ----

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"


def _run(cmd: list[str], timeout: int = 60) -> tuple[int, str, str]:
    """Run a CLI, return (code, stdout, stderr). Never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                            encoding="utf-8", errors="replace")
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except Exception as e:  # noqa: BLE001
        return 1, "", f"{type(e).__name__}: {e}"


def _clean(text: str, limit: int) -> str:
    text = re.sub(r"[ \t]+", " ", text or "")
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text[:limit]


# ---- SSRF egress guard (Python mirror of verity/src/net/safeFetch.ts) ----


class SsrfError(Exception):
    """Raised when an outbound URL targets a non-public / disallowed address."""


_ALLOWED_PORTS = {"", "80", "443", "8080", "8443"}


def _is_private_ip(ip: str) -> bool:
    """True for anything that is NOT a globally-routable public address — blocks loopback, RFC-1918,
    CGNAT (100.64/10), link-local incl. the 169.254.169.254 cloud-metadata endpoint, ULA, multicast,
    and reserved ranges (both IPv4 and IPv6, including IPv4-mapped IPv6)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return not addr.is_global


def _guard_url(url: str) -> None:
    """Validate ONE URL hop: http(s) only, standard port, and every resolved IP must be public."""
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ("http", "https"):
        raise SsrfError(f"blocked scheme: {p.scheme or '(none)'}")
    port = str(p.port) if p.port else ""
    if port not in _ALLOWED_PORTS:
        raise SsrfError(f"blocked port: {port}")
    host = p.hostname
    if not host:
        raise SsrfError("no host in URL")
    try:
        infos = socket.getaddrinfo(host, p.port or (443 if p.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except OSError:
        raise SsrfError(f"DNS resolution failed for {host}")
    if not infos:
        raise SsrfError(f"no addresses for {host}")
    for info in infos:
        ip = info[4][0]
        if _is_private_ip(ip):
            raise SsrfError(f"{host} resolves to a blocked address ({ip})")


def _resolve_safe_url(url: str, max_redirects: int = 4) -> str:
    """Follow redirects MANUALLY, validating every hop, and return the final public URL. This closes
    the 'public URL 302s to 127.0.0.1 / 169.254.169.254' redirect-SSRF that a single up-front check
    misses. The body is never downloaded here (stream + close) — this only resolves + validates hops."""
    current = url
    for _ in range(max_redirects + 1):
        _guard_url(current)
        try:
            r = requests.get(current, allow_redirects=False, stream=True, timeout=15, headers={"User-Agent": _UA})
        except Exception as e:  # noqa: BLE001
            raise SsrfError(f"fetch failed: {type(e).__name__}")
        try:
            loc = r.headers.get("location") if r.status_code in (301, 302, 303, 307, 308) else None
        finally:
            r.close()
        if loc:
            current = urllib.parse.urljoin(current, loc)
            continue
        return current
    raise SsrfError("too many redirects")


# ---- the fetch engine (Scrapling): read any page, stealth on block ----


def read_url(sb: SourceBook, url: str, max_chars: int = 6000) -> str:
    """Fetch a URL and return clean readable text. Tries a fast fetch first, then a
    stealth browser fetch (Cloudflare/anti-bot bypass) if the page blocks or is JS-only.
    SSRF-guarded: the URL and every redirect hop must resolve to a public address."""
    url = (url or "").strip()
    if not re.match(r"^https?://", url):
        return "ERROR: read_url needs a full http(s) URL."
    try:
        url = _resolve_safe_url(url)  # SSRF guard + manual redirect revalidation (blocks internal/metadata)
    except SsrfError as e:
        return f"ERROR: blocked URL ({e})."
    n = sb.add(url, via="web")

    def _extract(page) -> tuple[str, str]:
        title = ""
        try:
            t = page.css("title::text")
            title = (t[0].text if t else "").strip()
        except Exception:  # noqa: BLE001
            pass
        try:
            body = page.get_all_text(ignore_tags=("script", "style", "noscript"))
        except Exception:  # noqa: BLE001
            body = page.get_all_text() if hasattr(page, "get_all_text") else ""
        return title, body

    # 1) fast HTTP fetch
    try:
        from scrapling.fetchers import Fetcher
        page = Fetcher.get(url, timeout=25, stealthy_headers=True)
        if page.status == 200:
            title, body = _extract(page)
            if len(body.strip()) > 200:
                if title:
                    sb._sources[n - 1]["title"] = title[:180]
                return f"[source {n}] {url}\nTITLE: {title}\n\n{_clean(body, max_chars)}"
    except Exception:  # noqa: BLE001
        pass

    # 2) stealth browser fetch (bypasses anti-bot / renders JS)
    try:
        from scrapling.fetchers import StealthyFetcher
        page = StealthyFetcher.fetch(url, headless=True, network_idle=True, timeout=45000)
        title, body = _extract(page)
        if title:
            sb._sources[n - 1]["title"] = title[:180]
        if len(body.strip()) > 80:
            return f"[source {n}] {url} (stealth)\nTITLE: {title}\n\n{_clean(body, max_chars)}"
        return f"[source {n}] {url}\n(Reached the page but it returned little readable text — likely a login wall or media-only page.)"
    except Exception as e:  # noqa: BLE001
        return f"[source {n}] {url}\nERROR reaching page: {type(e).__name__}: {str(e)[:160]}"


# ---- open-web search (DuckDuckGo HTML — keyless) ----


_REACHABLE: dict[str, bool] = {}


def _host_reachable(host: str, port: int = 443, timeout: float = 2.5) -> bool:
    """Can we even open a socket to this host? Cached per process.

    Without this, a search engine that is network-blocked from the host still costs the full
    request budget before failing: a 20s POST plus a 40s stealth browser fetch, per engine. That is
    what turned a paid /search into a gateway timeout — the caller was charged and got a 502. A 2.5s
    connect probe turns "blocked" into "skipped" and lets a working engine answer inside budget.
    """
    if host in _REACHABLE:
        return _REACHABLE[host]
    ok = False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            ok = True
    except OSError:
        ok = False
    _REACHABLE[host] = ok
    return ok


def _ddg_html(query: str) -> str:
    """Fetch DuckDuckGo HTML results — via plain POST first, then Scrapling stealth if DDG
    throws its anomaly/rate-limit block (which it does under load)."""
    if not _host_reachable("html.duckduckgo.com"):
        return ""  # blocked from this host — do not burn the budget proving it again
    url = "https://html.duckduckgo.com/html/?q=" + urllib.parse.quote(query)
    try:
        r = requests.post("https://html.duckduckgo.com/html/", data={"q": query},
                          headers={"User-Agent": _UA}, timeout=8)
        if r.status_code == 200 and "result__a" in r.text:
            return r.text
    except Exception:  # noqa: BLE001
        pass
    # blocked/empty -> stealth browser bypass (this is what Scrapling is for)
    try:
        from scrapling.fetchers import StealthyFetcher
        page = StealthyFetcher.fetch(url, headless=True, network_idle=True, timeout=12000)
        return page.html_content or ""
    except Exception:  # noqa: BLE001
        return ""


def _bing_html(query: str) -> str:
    """Fallback search: Bing HTML via stealth fetch."""
    url = "https://www.bing.com/search?q=" + urllib.parse.quote(query)
    try:
        from scrapling.fetchers import StealthyFetcher
        page = StealthyFetcher.fetch(url, headless=True, network_idle=True, timeout=40000)
        return page.html_content or ""
    except Exception:  # noqa: BLE001
        try:
            return requests.get(url, headers={"User-Agent": _UA}, timeout=20).text
        except Exception:  # noqa: BLE001
            return ""


def _unwrap_bing(href: str) -> str:
    """Turn a bing.com/ck/a?...&u=a1<base64> redirector into the real target URL.

    Citing the redirector would make every source look like it came from Bing, which defeats the
    point of citing at all — a reader must be able to see and check the actual source.
    """
    if "bing.com/ck/a" not in href:
        return href
    try:
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(href).query)
        u = (q.get("u") or [""])[0]
        if u.startswith("a1"):
            u = u[2:]
        pad = "=" * (-len(u) % 4)
        decoded = base64.urlsafe_b64decode(u + pad).decode("utf-8", "replace")
        return decoded if decoded.startswith(("http://", "https://")) else href
    except Exception:  # noqa: BLE001
        return href


def _brave_html(query: str) -> str:
    """Brave results via stealth fetch. Keyless, and the only engine measured to answer correctly on
    queries whose first token is a common word (see _relevance)."""
    url = "https://search.brave.com/search?q=" + urllib.parse.quote(query)
    try:
        from scrapling.fetchers import StealthyFetcher
        page = StealthyFetcher.fetch(url, headless=True, network_idle=True, timeout=35000)
        return page.html_content or ""
    except Exception:  # noqa: BLE001
        return ""


def _brave_results(query: str, num: int, sb: SourceBook, Selector) -> list[str]:
    """Brave results in the shared '[source n] title / url / snippet' form."""
    html = _brave_html(query)
    if not html:
        return []
    found: list[str] = []
    try:
        sel = Selector(html)
        # `div[data-type=web]` is the organic block; `.snippet` also matches the answer/AI cards, so it
        # is only a fallback when the primary selector finds nothing.
        blocks = sel.css("div[data-type=web]") or sel.css("div.snippet")
        for el in blocks[:num]:
            anchors = el.css("a")
            if not anchors:
                continue
            real = anchors[0].attrib.get("href", "")
            if not real.startswith("http"):
                continue
            t = el.css(".title")
            s = el.css(".snippet-description") or el.css(".snippet-content")
            title = t[0].text.strip() if t and hasattr(t[0], "text") else ""
            snip = s[0].text.strip() if s and hasattr(s[0], "text") else ""
            n = sb.add(real, title=title, via="search")
            found.append(f"[source {n}] {title}\n  {real}\n  {snip[:220]}")
    except Exception:  # noqa: BLE001
        pass
    return found


# A query term shorter than this, or in this set, cannot discriminate between results.
_QUERY_STOPWORDS = frozenset({
    "the", "and", "for", "with", "what", "how", "why", "who", "does", "did", "was", "are", "its",
    "from", "into", "about", "that", "this", "then", "than", "there", "their", "which", "when",
})


def _relevance(query: str, blob: str) -> float:
    """Fraction of the query's DISCRIMINATING terms that appear anywhere in a result set.

    This exists because of a measured failure that no amount of engine-picking prevents on its own:
    the query "X Layer OKX rollup architecture" returned six results about Twitter and Google's
    Moonshot Factory, because the engine latched onto the leading token "X". Every result was
    off-target and the response still reported ok:true with result_count 6 — a confident false
    positive, which is worse for a calling agent than an honest empty answer, because it gets cited.

    Single characters and common words are excluded: "X" alone matches x.com and would score that
    disaster as a perfect hit.
    """
    terms = {t for t in re.findall(r"[A-Za-z0-9]{3,}", (query or "").lower())
             if t not in _QUERY_STOPWORDS}
    if not terms:
        return 1.0  # nothing discriminating to check — do not punish the engine for the query
    low = (blob or "").lower()
    return sum(1 for t in terms if t in low) / len(terms)


def _bing_results(query: str, num: int, sb: SourceBook, Selector) -> list[str]:
    """Bing results, parsed into the shared '[source n] title / url / snippet' form."""
    html = _bing_html(query)
    if not html:
        return []
    found: list[str] = []
    try:
        sel = Selector(html)
        for li in sel.css("li.b_algo")[:num]:
            a = li.css_first("h2 a") if hasattr(li, "css_first") else None
            a = a or (li.css("h2 a")[0] if li.css("h2 a") else None)
            if not a:
                continue
            real = _unwrap_bing(a.attrib.get("href", ""))
            title = a.text.strip() if hasattr(a, "text") else ""
            cap = li.css("p")
            snip = cap[0].text.strip() if cap and hasattr(cap[0], "text") else ""
            n = sb.add(real, title=title, via="search")
            found.append(f"[source {n}] {title}\n  {real}\n  {snip[:220]}")
    except Exception:  # noqa: BLE001
        pass
    return found


def web_search(sb: SourceBook, query: str, num: int = 8) -> str:
    """Search the open web. Returns ranked results (title, url, snippet). Keyless and
    resilient: DuckDuckGo (stealth-bypassed if rate-limited), Bing fallback."""
    query = (query or "").strip()
    if not query:
        return "ERROR: empty query."

    from scrapling.parser import Selector

    def _ddg(q: str, n: int) -> list[str]:
        html = _ddg_html(q)
        if not html or "result__a" not in html:
            return []
        got: list[str] = []
        try:
            sel = Selector(html)
            anchors = sel.css("a.result__a")
            snippets = sel.css("a.result__snippet")
            for i, a in enumerate(anchors[:n]):
                href = a.attrib.get("href", "")
                m = re.search(r"uddg=([^&]+)", href)
                real = urllib.parse.unquote(m.group(1)) if m else href
                title = a.text.strip() if hasattr(a, "text") else ""
                snip = snippets[i].text.strip() if i < len(snippets) and hasattr(snippets[i], "text") else ""
                sn = sb.add(real, title=title, via="search")
                got.append(f"[source {sn}] {title}\n  {real}\n  {snip[:220]}")
        except Exception:  # noqa: BLE001
            pass
        return got

    # Engine order is measured, not assumed.
    #  * DuckDuckGo first WHEN REACHABLE — cleanest markup and real target URLs — but it answers 202
    #    (anomaly block) from this host under load, and probing it first once burned most of the
    #    request budget on a paid call, so an unreachable host is skipped outright.
    #  * Brave next: on the query "X Layer OKX rollup architecture" it returned the OKX developer docs
    #    while Bing returned six links about Twitter. Brave is keyless and was not rate-limited.
    #  * Bing last: it works for ordinary queries but collapses to the leading token on queries that
    #    begin with a common word, which is exactly the failure this ordering exists to survive.
    engines: list[tuple[str, callable]] = []
    if _host_reachable("html.duckduckgo.com"):
        engines.append(("duckduckgo", _ddg))
    engines.append(("brave", lambda q, n: _brave_results(q, n, sb, Selector)))
    engines.append(("bing", lambda q, n: _bing_results(q, n, sb, Selector)))

    # Keep the best attempt seen. An engine that returns SOMETHING off-target is still better than
    # nothing if every engine fails, but it must never be presented as a clean hit.
    best: list[str] = []
    best_score = -1.0
    best_engine = ""
    for name, fn in engines:
        try:
            got = fn(query, num)
        except Exception:  # noqa: BLE001
            continue
        if not got:
            continue
        score = _relevance(query, "\n".join(got))
        if score > best_score:
            best, best_score, best_engine = got, score, name
        # Half the discriminating terms present is a real answer; stop and spend no more budget.
        if score >= 0.5:
            break

    if not best:
        return (f"No results found for: {query} (search sources are rate-limited right now — try "
                f"read_url on a known source, or a different query).")

    header = f"Web search — '{query}' ({len(best)} results):"
    if best_score < 0.5:
        # Say so IN THE DELIVERABLE. A calling agent reads this text and would otherwise cite six
        # confidently-returned but unrelated pages.
        header = (f"Web search — '{query}' ({len(best)} results, LOW CONFIDENCE): the search engines "
                  f"returned results that do not appear to match this query (matched "
                  f"{best_score:.0%} of its distinctive terms). Treat these as unverified and consider "
                  f"rephrasing.")
    return header + "\n\n" + "\n\n".join(best)


# ---- Twitter / X (walled garden) ----


# `status/<id>` first: a bare-number fallback with a length floor rejected real short ids (tweet 20,
# the first tweet ever posted) while also risking a match on some unrelated number in the path.
_TWEET_ID = re.compile(r"status(?:es)?/(\d+)|^\s*(\d{6,25})\s*$")


def twitter_thread(sb: SourceBook, url_or_id: str) -> str:
    """Read one public tweet in full — author, text, timestamp, engagement, quoted tweet.

    Uses X's public syndication endpoint, which needs no login and no cookie. Verified against
    tweet id 20 (@jack, "just setting up my twttr"). This is the part of X that is genuinely
    readable without an account, so it is exposed unconditionally.
    """
    m = _TWEET_ID.search(url_or_id or "")
    if not m:
        return "twitter_thread needs a tweet URL or numeric id."
    tid = m.group(1) or m.group(2)
    try:
        j = _api_json(f"https://cdn.syndication.twimg.com/tweet-result?id={tid}&lang=en&token=a")
    except Exception as e:  # noqa: BLE001
        return f"twitter_thread failed: {type(e).__name__}: {str(e)[:140]}"
    user = (j or {}).get("user") or {}
    text = (j or {}).get("text")
    if not text:
        # A deleted, protected or non-existent tweet returns 200 with empty fields. Say so — do not
        # let the model infer content that was never returned.
        return (f"Tweet {tid} could not be read: it is deleted, private, or does not exist. "
                f"X returned an empty record, not an error.")
    link = f"https://x.com/{user.get('screen_name','i')}/status/{tid}"
    n = sb.add(link, title=f"@{user.get('screen_name','?')} on X", via="twitter")
    parts = [f"[source {n}] @{user.get('screen_name')} ({user.get('name')})"
             f"{' · verified' if user.get('is_blue_verified') else ''}",
             f"  {link}",
             f"  posted: {j.get('created_at','?')}",
             f"  likes {j.get('favorite_count',0):,} · replies {j.get('conversation_count',0):,}",
             "", _clean(text, 2000)]
    q = j.get("quoted_tweet") or {}
    if q.get("text"):
        parts += ["", f"  quoting @{(q.get('user') or {}).get('screen_name','?')}: {_clean(q['text'], 600)}"]
    return "\n".join(parts)


def _x_cookie() -> tuple[str, str]:
    import os
    return os.environ.get("X_AUTH_TOKEN", "").strip(), os.environ.get("X_CT0", "").strip()


def twitter_search(sb: SourceBook, query: str, n: int = 15) -> str:
    """Search live X posts. Requires an operator-supplied session, because X has no keyless search.

    Kept strictly separate from twitter_thread: reading one public tweet needs nothing, searching
    needs a logged-in session. Conflating them would let the service advertise a reach it only
    sometimes has.
    """
    auth, ct0 = _x_cookie()
    if not (auth and ct0):
        return ("twitter_search is not available: X has no keyless search endpoint and this host has "
                "no X session configured. Use web_search (which indexes public X posts) or "
                "twitter_thread for a specific tweet.")
    url = ("https://api.x.com/2/search/adaptive.json?q=" + urllib.parse.quote(query)
           + f"&count={max(5, min(int(n or 15), 30))}&tweet_search_mode=live&query_source=typed_query")
    hdrs = {
        # Public web bearer — the same one x.com ships to logged-out browsers.
        "Authorization": ("Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D"
                          "1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"),
        "x-csrf-token": ct0,
        "Cookie": f"auth_token={auth}; ct0={ct0}",
        "x-twitter-auth-type": "OAuth2Session",
        "x-twitter-active-user": "yes",
    }
    try:
        j = _api_json(url, hdrs, timeout=30)
    except Exception as e:  # noqa: BLE001
        return (f"twitter_search could not reach X ({type(e).__name__}). The configured session may "
                f"have expired — sessions are not renewable automatically. Falling back is safer: "
                f"use web_search for public X content.")
    tweets = ((j or {}).get("globalObjects") or {}).get("tweets") or {}
    users = ((j or {}).get("globalObjects") or {}).get("users") or {}
    if not tweets:
        return f"X returned no live posts for '{query}'."
    rows = sorted(tweets.values(), key=lambda t: t.get("favorite_count", 0), reverse=True)[:12]
    out = []
    for t in rows:
        u = users.get(str(t.get("user_id_str") or ""), {})
        handle = u.get("screen_name", "?")
        link = f"https://x.com/{handle}/status/{t.get('id_str')}"
        k = sb.add(link, title=f"@{handle} on X", via="twitter")
        out.append(f"[source {k}] @{handle} · likes {t.get('favorite_count',0):,}\n  {link}\n"
                   f"  {_clean(t.get('full_text') or t.get('text') or '', 400)}")
    return f"X — live posts for '{query}':\n\n" + "\n\n".join(out)


# ---- Reddit (walled garden) ----


def reddit_search(sb: SourceBook, query: str) -> str:
    """Search Reddit for community discussion.

    Reddit's public JSON now answers 403 to datacenter IPs even with a browser user-agent (checked
    against both www and old.reddit), so this needs an operator-supplied session. Without one it says
    so rather than returning nothing and letting the model assume the topic is undiscussed.
    """
    import os
    cookie = os.environ.get("REDDIT_COOKIE", "").strip()
    if not cookie:
        return ("reddit_search is not available: Reddit blocks unauthenticated reads from this host "
                "(403) and no Reddit session is configured. Use hn_search for practitioner discussion, "
                "or web_search, which indexes public Reddit threads.")
    u = ("https://www.reddit.com/search.json?limit=8&sort=relevance&t=year&q="
         + urllib.parse.quote(query))
    try:
        j = _api_json(u, {"Cookie": cookie}, timeout=30)
    except Exception as e:  # noqa: BLE001
        return (f"reddit_search could not reach Reddit ({type(e).__name__}). The configured session may "
                f"have expired; sessions are not renewable automatically. Use hn_search or web_search.")
    kids = ((j or {}).get("data") or {}).get("children") or []
    if not kids:
        return f"Reddit returned no threads for '{query}'."
    out = []
    for c in kids:
        d = c.get("data") or {}
        link = "https://www.reddit.com" + (d.get("permalink") or "")
        n = sb.add(link, title=(d.get("title") or "")[:140], via="reddit")
        body = _clean(d.get("selftext") or "", 350)
        out.append(f"[source {n}] r/{d.get('subreddit','?')} — {(d.get('title') or '')[:140]}\n"
                   f"  {d.get('score',0):,} points · {d.get('num_comments',0):,} comments\n  {link}"
                   + (f"\n  {body}" if body else ""))
    return f"Reddit — discussions for '{query}':\n\n" + "\n\n".join(out)


# ---- YouTube (transcripts of the walled garden) ----


def youtube(sb: SourceBook, url: str) -> str:
    """Get a YouTube video's metadata + transcript (auto-subs) so its content can be
    researched as text. yt-dlp under the hood."""
    if not shutil.which("yt-dlp"):
        return "youtube tool unavailable."
    code, out, err = _run(["yt-dlp", "--dump-json", "--skip-download", url], timeout=60)
    if code != 0 or not out.strip():
        return f"youtube failed: {(err or out)[:160]}"
    try:
        meta = json.loads(out.splitlines()[0])
    except Exception:  # noqa: BLE001
        return "youtube: could not parse metadata."
    n = sb.add(url, title=meta.get("title", "")[:180], via="youtube")
    parts = [
        f"[source {n}] {url}",
        f"TITLE: {meta.get('title','')}",
        f"CHANNEL: {meta.get('uploader','')} | views: {meta.get('view_count','?')} | {meta.get('upload_date','')}",
        f"DESCRIPTION: {(meta.get('description') or '')[:800]}",
    ]
    # transcript from auto/normal subs if present
    subs = meta.get("automatic_captions") or meta.get("subtitles") or {}
    en = subs.get("en") or subs.get("en-US") or next(iter(subs.values()), None)
    if en:
        for track in en:
            if track.get("url") and track.get("ext") in ("json3", "srv1", "vtt", "ttml"):
                try:
                    tr = requests.get(track["url"], timeout=20, headers={"User-Agent": _UA}).text
                    txt = re.sub(r"<[^>]+>", " ", tr)
                    txt = re.sub(r'"[a-zA-Z_]+":', " ", txt)
                    txt = re.sub(r"[{}\[\]\"]", " ", txt)
                    txt = _clean(txt, 5000)
                    if len(txt) > 200:
                        parts.append(f"\nTRANSCRIPT (excerpt):\n{txt}")
                        break
                except Exception:  # noqa: BLE001
                    pass
    return "\n".join(parts)


# ---- GitHub (developer world) ----


def _api_json(url: str, headers: dict | None = None, timeout: int = 25) -> Any:
    """GET a JSON API directly. No CLI, so the capability exists wherever this runs.

    The CLI-backed versions of these tools answered "tool unavailable on this host" in production,
    because `gh`, `twitter` and `rdt` are only installed on a developer laptop. A hosted paid service
    cannot depend on someone's workstation, so the channels that have a keyless HTTP endpoint now use
    it directly.
    """
    h = {"User-Agent": _UA, "Accept": "application/json"}
    if headers:
        h.update(headers)
    r = requests.get(url, headers=h, timeout=timeout)
    r.raise_for_status()
    return r.json()


def github_search(sb: SourceBook, query: str) -> str:
    """Search GitHub repositories. Keyless REST API; GITHUB_TOKEN only raises the rate limit."""
    import os
    hdr = {}
    tok = os.environ.get("GITHUB_TOKEN", "").strip()
    if tok:
        hdr["Authorization"] = f"Bearer {tok}"
    u = ("https://api.github.com/search/repositories?per_page=8&sort=stars&order=desc&q="
         + urllib.parse.quote(query))
    try:
        j = _api_json(u, hdr)
    except Exception as e:  # noqa: BLE001
        return f"github_search failed: {type(e).__name__}: {str(e)[:140]}"
    items = j.get("items") or []
    if not items:
        return f"GitHub returned no repositories for '{query}'."
    lines = []
    for r in items:
        n = sb.add(r.get("html_url", ""), title=r.get("full_name", ""), via="github")
        lines.append(f"[source {n}] {r.get('full_name','')} ★{r.get('stargazers_count',0):,}"
                     f"  ({r.get('language') or 'n/a'})\n  {r.get('html_url','')}\n"
                     f"  {(r.get('description') or '')[:180]}")
    return (f"GitHub — {j.get('total_count',0):,} repositories match '{query}'. Top {len(items)} by stars:"
            f"\n\n" + "\n\n".join(lines))


def hn_search(sb: SourceBook, query: str) -> str:
    """Search Hacker News stories and comments — what engineers actually said about something.

    Keyless (Algolia). This is the honest substitute for the login-gated forums: real practitioner
    opinion, fully public, and it cannot silently expire the way a session cookie does.
    """
    u = ("https://hn.algolia.com/api/v1/search?hitsPerPage=8&tags=(story,comment)&query="
         + urllib.parse.quote(query))
    try:
        j = _api_json(u)
    except Exception as e:  # noqa: BLE001
        return f"hn_search failed: {type(e).__name__}: {str(e)[:140]}"
    hits = j.get("hits") or []
    if not hits:
        return f"Hacker News has no discussion matching '{query}'."
    hits = sorted(hits, key=lambda h: ((h.get("points") or 0), (h.get("num_comments") or 0)), reverse=True)
    lines = []
    for h in hits:
        oid = h.get("objectID")
        link = f"https://news.ycombinator.com/item?id={oid}"
        title = h.get("title") or h.get("story_title") or "(comment)"
        n = sb.add(link, title=title[:120], via="hackernews")
        body = re.sub(r"<[^>]+>", " ", h.get("comment_text") or h.get("story_text") or "")
        meta = f"{h.get('points') or 0} points, {h.get('num_comments') or 0} comments"
        lines.append(f"[source {n}] {title[:120]}  ({meta})\n  {link}"
                     + (f"\n  {_clean(body, 400)}" if body.strip() else ""))
    return (f"Hacker News — {j.get('nbHits',0):,} results for '{query}'. Top {len(hits)}:\n\n"
            + "\n\n".join(lines))


def rss_read(sb: SourceBook, url: str) -> str:
    """Read an RSS or Atom feed and return its recent entries as text. Keyless."""
    _guard_url(url)
    try:
        r = requests.get(url, timeout=25, headers={
            "User-Agent": _UA, "Accept-Encoding": "gzip, deflate",
            "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*"})
        r.raise_for_status()
        xml = r.text
    except Exception as e:  # noqa: BLE001
        return f"rss_read failed: {type(e).__name__}: {str(e)[:140]}"
    items = re.findall(r"<(?:item|entry)\b.*?</(?:item|entry)>", xml, re.S | re.I)[:12]
    if not items:
        return f"No feed entries found at {url} (is it really RSS/Atom?)."
    feed_n = sb.add(url, title="feed", via="rss")
    out = [f"[source {feed_n}] feed: {url}", ""]
    for it in items:
        t = re.search(r"<title[^>]*>(.*?)</title>", it, re.S | re.I)
        l = re.search(r"<link[^>]*>(.*?)</link>", it, re.S | re.I) or re.search(r'<link[^>]*href="([^"]+)"', it, re.I)
        d = re.search(r"<(?:pubDate|updated|published)[^>]*>(.*?)</", it, re.S | re.I)
        def _t(m):
            s = re.sub(r"<!\[CDATA\[(.*?)\]\]>", r"\1", m.group(1), flags=re.S) if m else ""
            return re.sub(r"<[^>]+>", " ", s).strip()
        title, link, when = _t(t), _t(l), _t(d)
        if link:
            n = sb.add(link, title=title[:120], via="rss")
            out.append(f"[source {n}] {title[:140]}{('  ' + when) if when else ''}\n  {link}")
        else:
            out.append(f"- {title[:140]}{('  ' + when) if when else ''}")
    return "\n".join(out)


# ---- the tool registry Fable sees (Anthropic tool schema) ----


def build_toolset(sb: SourceBook) -> tuple[list[dict], dict[str, Callable[..., str]]]:
    """Returns (tool_schemas_for_fable, dispatch_map). The schemas describe each power
    to the model; the model decides which to call and when."""
    schemas = [
        {
            "name": "web_search",
            "description": "Search the open web for a query and get ranked results (title, URL, snippet). Use this to discover sources on ANY topic. Call it multiple times with different angles.",
            "input_schema": {"type": "object", "properties": {
                "query": {"type": "string", "description": "the search query"},
                "num": {"type": "integer", "description": "how many results (default 8)"},
            }, "required": ["query"]},
        },
        {
            "name": "read_url",
            "description": "Open a web page and read its full clean text. Works on hard/anti-bot/JS pages (stealth fallback). Use after web_search to read the promising sources in depth.",
            "input_schema": {"type": "object", "properties": {
                "url": {"type": "string", "description": "full http(s) URL"},
            }, "required": ["url"]},
        },
    ]
    dispatch: dict[str, Callable[..., str]] = {
        "web_search": lambda query, num=8: web_search(sb, query, int(num or 8)),
        "read_url": lambda url: read_url(sb, url),
    }
    # Keyless channels. These talk to public HTTP APIs, so they work wherever the service runs and
    # cannot expire. Previously they were gated behind a CLI (`gh`, `twitter`) that only exists on a
    # developer laptop, which meant production silently never had them.
    keyless = [
        ("github_search", lambda query: github_search(sb, query),
         "Search GitHub repositories by topic — stars, language, description, URL. Use for software, "
         "tooling and the open-source landscape around a subject.",
         {"query": {"type": "string"}}, ["query"]),
        ("hn_search", lambda query: hn_search(sb, query),
         "Search Hacker News stories AND comments — what engineers and founders actually said about "
         "something, with points and comment counts. Best source for candid practitioner opinion.",
         {"query": {"type": "string"}}, ["query"]),
        ("twitter_thread", lambda url_or_id: twitter_thread(sb, url_or_id),
         "Read one public tweet/X post in full from its URL or id — author, text, timestamp, likes, "
         "and any quoted post. Use when a source or claim points at a specific tweet.",
         {"url_or_id": {"type": "string", "description": "an x.com/twitter.com status URL or numeric id"}},
         ["url_or_id"]),
        ("rss_read", lambda url: rss_read(sb, url),
         "Read an RSS or Atom feed and list its recent entries with links. Use for blogs, changelogs "
         "and newsrooms that publish a feed.",
         {"url": {"type": "string", "description": "the feed URL"}}, ["url"]),
    ]
    for name, fn, desc, props, required in keyless:
        schemas.append({"name": name, "description": desc,
                        "input_schema": {"type": "object", "properties": props, "required": required}})
        dispatch[name] = fn

    # CLI-backed: still self-guarding, because a missing binary is a real absence.
    if shutil.which("yt-dlp"):
        schemas.append({"name": "youtube", "description":
                        "Given a YouTube URL, get the video's title, channel, description and full "
                        "transcript as text, so its content can be researched and quoted.",
                        "input_schema": {"type": "object", "properties": {
                            "url": {"type": "string", "description": "a youtube.com or youtu.be URL"}},
                            "required": ["url"]}})
        dispatch["youtube"] = lambda url: youtube(sb, url)

    # Session-backed: only offered when an operator has actually configured a session, so the model is
    # never handed a tool that can only answer "not configured", and a buyer is never charged for a
    # reach this host cannot currently make.
    import os
    if os.environ.get("X_AUTH_TOKEN") and os.environ.get("X_CT0"):
        schemas.append({"name": "twitter_search", "description":
                        "Search LIVE X/Twitter posts for a query — current sentiment, breaking takes "
                        "and primary voices. X has no keyless search, so this exists only on hosts "
                        "with a configured session.",
                        "input_schema": {"type": "object", "properties": {
                            "query": {"type": "string"}}, "required": ["query"]}})
        dispatch["twitter_search"] = lambda query: twitter_search(sb, query)
    if os.environ.get("REDDIT_COOKIE"):
        schemas.append({"name": "reddit_search", "description":
                        "Search Reddit threads for community discussion and lived experience — what "
                        "real users say about a topic, with score and comment counts.",
                        "input_schema": {"type": "object", "properties": {
                            "query": {"type": "string"}}, "required": ["query"]}})
        dispatch["reddit_search"] = lambda query: reddit_search(sb, query)
    return schemas, dispatch
