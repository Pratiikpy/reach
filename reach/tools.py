"""
Reach — the tool layer the research agent (Claude Fable 5) drives autonomously.

Each tool reaches a different part of the internet and returns clean, LLM-ready text
plus the source URLs it touched (so every claim in the final report can be cited).

Powers combined here (each optional tool self-guards on whether its CLI is installed):
  - open web        : web_search (DuckDuckGo, keyless) + read_url (Scrapling, stealth-capable)
  - developer world : github_search, youtube (transcripts)
  - login-gated     : twitter_search, reddit_search — only exposed when their CLIs are installed
                      on this host; the deployed engine currently runs open-web + stealth-read +
                      github + youtube.

Scrapling (BSD-3) provides the fetch engine — StealthyFetcher bypasses Cloudflare/anti-bot;
agent-reach (MIT) provides the routed CLIs (twitter-cli, rdt-cli, yt-dlp, gh) for the
login-gated platforms. See THIRD_PARTY_LICENSES.md.
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


def twitter_search(sb: SourceBook, query: str, n: int = 15) -> str:
    """Search live Twitter/X for a query — what real people are posting right now.
    ChatGPT/Perplexity cannot read this; a logged-in session (agent-reach) can."""
    if not shutil.which("twitter"):
        return "twitter tool unavailable on this host."
    code, out, err = _run(["twitter", "search", query, "-n", str(n)], timeout=50)
    if code != 0 or not out.strip():
        return f"twitter_search failed: {(err or out)[:160]}"
    sb.add(f"https://x.com/search?q={urllib.parse.quote(query)}", title=f"X search: {query}", via="twitter")
    return f"Twitter/X — live posts for '{query}':\n\n{_clean(out, 4500)}"


def twitter_thread(sb: SourceBook, url_or_id: str) -> str:
    """Read a specific tweet/thread in full."""
    if not shutil.which("twitter"):
        return "twitter tool unavailable."
    code, out, err = _run(["twitter", "tweet", url_or_id], timeout=45)
    if code != 0:
        return f"twitter_thread failed: {(err or out)[:160]}"
    sb.add(url_or_id if url_or_id.startswith("http") else f"https://x.com/i/status/{url_or_id}",
           title="X thread", via="twitter")
    return _clean(out, 4000)


# ---- Reddit (walled garden) ----


def reddit_search(sb: SourceBook, query: str) -> str:
    """Search Reddit — honest community opinion. Best-effort (session may need refresh)."""
    if not shutil.which("rdt"):
        return "reddit tool unavailable on this host."
    code, out, err = _run(["rdt", "search", query], timeout=50)
    if code != 0 or not out.strip():
        return f"reddit_search unavailable right now ({(err or 'no output')[:100]}). Rely on other sources."
    sb.add(f"https://www.reddit.com/search/?q={urllib.parse.quote(query)}",
           title=f"Reddit search: {query}", via="reddit")
    return f"Reddit — discussions for '{query}':\n\n{_clean(out, 4500)}"


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


def github_search(sb: SourceBook, query: str) -> str:
    """Search GitHub repos/code for a query. gh CLI under the hood."""
    if not shutil.which("gh"):
        return "github tool unavailable."
    code, out, err = _run(
        ["gh", "search", "repos", query, "--limit", "8",
         "--json", "fullName,description,stargazersCount,url,updatedAt"],
        timeout=45,
    )
    if code != 0 or not out.strip():
        return f"github_search failed: {(err or out)[:160]}"
    try:
        rows = json.loads(out)
    except Exception:  # noqa: BLE001
        return _clean(out, 3000)
    lines = []
    for r in rows:
        n = sb.add(r.get("url", ""), title=r.get("fullName", ""), via="github")
        lines.append(f"[source {n}] {r.get('fullName','')} ★{r.get('stargazersCount',0)}\n"
                     f"  {r.get('url','')}\n  {(r.get('description') or '')[:160]}")
    return "GitHub repos for '" + query + "':\n\n" + "\n\n".join(lines)


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
    # Optional walled-garden / developer channels — only exposed to the model when the backing CLI is
    # actually installed, so it never wastes a round on a tool that would just answer "unavailable"
    # (and Reach never advertises a reach it can't currently make).
    optional = [
        ("twitter", "twitter_search", lambda query: twitter_search(sb, query),
         "Search LIVE Twitter/X for what real people are posting right now — sentiment, breaking takes, primary voices inside the walled garden.",
         {"query": {"type": "string"}}, ["query"]),
        ("rdt", "reddit_search", lambda query: reddit_search(sb, query),
         "Search Reddit for honest community discussion and lived experience on a topic — 'what do real users actually think'.",
         {"query": {"type": "string"}}, ["query"]),
        ("yt-dlp", "youtube", lambda url: youtube(sb, url),
         "Given a YouTube URL, get the video's title, channel, description and transcript as text.",
         {"url": {"type": "string", "description": "a youtube.com or youtu.be URL"}}, ["url"]),
        ("gh", "github_search", lambda query: github_search(sb, query),
         "Search GitHub for repositories/projects matching a query (stars, description, URL). Use for software, tools, open-source landscape.",
         {"query": {"type": "string"}}, ["query"]),
    ]
    for cli, name, fn, desc, props, required in optional:
        if shutil.which(cli):
            schemas.append({"name": name, "description": desc,
                            "input_schema": {"type": "object", "properties": props, "required": required}})
            dispatch[name] = fn
    return schemas, dispatch
