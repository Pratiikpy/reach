"""The page a human sees at https://reach.ivaronix.xyz/.

Reach's base URL returned a bare `404 {"detail":"Not Found"}` — every registered endpoint is a POST,
so nothing answered a plain browser GET. That is what a reviewer, a judge, or anyone following the
marketplace listing opens FIRST, and a 404 there reads as a dead service no matter how well the paid
endpoints work.

Deliberately server-rendered from the same constants the API serves, so the prices and paths on this
page cannot drift away from the ones the paywall actually charges. No external assets: the page must
render with no network beyond itself.
"""
from __future__ import annotations

SERVICES = [
    ("POST", "/research", "0.05",
     "Deep multi-round research on any question. Reads and credibility-ranks live sources, then returns "
     "findings where every claim cites a source it actually opened.",
     '{"question": "What secures X Layer?", "max_rounds": 4}'),
    ("POST", "/search", "0.01",
     "Live open-web search returning ranked results with their URLs.",
     '{"query": "X Layer rollup architecture", "num": 8}'),
    ("POST", "/read", "0.01",
     "Fetches a URL and returns its readable text content.",
     '{"url": "https://example.com"}'),
]

_CSS = """
:root{--bg:#0a0e1a;--panel:#111726;--line:#1e2740;--ink:#e8edf7;--dim:#8d9ab5;
--teal:#48e8b2;--gold:#f6d084;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:16px/1.65 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
-webkit-font-smoothing:antialiased}
.wrap{max-width:900px;margin:0 auto;padding:56px 22px 80px}
header{border-bottom:1px solid var(--line);padding-bottom:26px;margin-bottom:34px}
h1{margin:0 0 6px;font-size:31px;letter-spacing:-.02em}
h1 span{color:var(--teal)}
.tag{color:var(--dim);font-size:16px;margin:0}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.13em;color:var(--dim);
margin:38px 0 14px;font-weight:600}
.svc{border:1px solid var(--line);border-radius:11px;padding:17px 19px;margin-bottom:13px;
background:var(--panel)}
.svc-h{display:flex;flex-wrap:wrap;align-items:baseline;gap:10px;margin-bottom:7px}
.verb{font:600 11px/1 var(--mono);color:var(--bg);background:var(--teal);
padding:4px 7px;border-radius:4px;letter-spacing:.06em}
.path{font:600 15px/1 var(--mono);color:var(--ink)}
.price{margin-left:auto;font:600 14px/1 var(--mono);color:var(--gold);white-space:nowrap}
.desc{color:var(--dim);font-size:14.5px;margin:0 0 11px}
pre{margin:0;padding:11px 13px;background:#080c16;border:1px solid var(--line);
border-radius:7px;overflow-x:auto;font:13px/1.5 var(--mono);color:#b9c6e2}
code{font-family:var(--mono)}
.steps{counter-reset:s;list-style:none;padding:0;margin:0}
.steps li{counter-increment:s;position:relative;padding:0 0 13px 34px;color:var(--dim);font-size:14.5px}
.steps li::before{content:counter(s);position:absolute;left:0;top:1px;width:21px;height:21px;
border-radius:50%;background:var(--panel);border:1px solid var(--line);color:var(--teal);
font:600 11px/21px var(--mono);text-align:center}
.steps b{color:var(--ink);font-weight:600}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(215px,1fr));gap:11px}
.meta div{border:1px solid var(--line);border-radius:9px;padding:12px 14px;background:var(--panel)}
.meta dt{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.1em;margin-bottom:4px}
/* break-all split "/health" across lines mid-word; anywhere only breaks when a token cannot fit. */
.meta dd{margin:0;font:13px/1.45 var(--mono);color:var(--ink);overflow-wrap:anywhere}
footer{margin-top:44px;padding-top:22px;border-top:1px solid var(--line);color:var(--dim);font-size:13px}
a{color:var(--teal)}
@media(max-width:560px){.wrap{padding:34px 16px 56px}h1{font-size:25px}.price{margin-left:0}}
"""


def landing_html(signer: str | None, models: list[str] | str) -> str:
    # Show the PREFERENCE ORDER, not a single name. The router gates models individually, so the
    # configured first choice is frequently not the model that serves; printing it alone would
    # advertise a model that never runs. Each report states the model that actually wrote it.
    chain = [models] if isinstance(models, str) else list(models)
    model = " → ".join(chain[:4]) + (" → …" if len(chain) > 4 else "")
    rows = "".join(
        f"""<div class="svc"><div class="svc-h"><span class="verb">{verb}</span>
<span class="path">{path}</span><span class="price">${price} USD₮0</span></div>
<p class="desc">{desc}</p><pre>curl -X POST https://reach.ivaronix.xyz{path} \\
  -H 'Content-Type: application/json' \\
  -d '{example}'</pre></div>"""
        for verb, path, price, desc, example in SERVICES
    )
    signer_line = signer or "not configured"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Reach — research with sources you can check</title>
<meta name="description" content="An OKX.AI agent service: pay-per-call web research, search and read over x402 on X Layer. Every claim cites a source it actually opened.">
<style>{_CSS}</style></head><body><div class="wrap">
<header>
<h1>Reach<span>.</span></h1>
<p class="tag">Research with sources you can check — pay per call, no account, no subscription.</p>
</header>

<p style="color:var(--dim);margin:0 0 8px">Reach answers a question by going out to the live internet,
reading what it finds, and returning a report where <b style="color:var(--ink)">every claim is tied to a
source it actually opened</b>. Each report is signed, so anyone can verify it came from Reach and was
not altered afterwards.</p>

<h2>Services</h2>
{rows}

<h2>How paying works (x402)</h2>
<ol class="steps">
<li>Call the endpoint with no payment. It answers <b>402</b> with a <code>PAYMENT-REQUIRED</code> header
containing the challenge.</li>
<li>Sign the challenge with your wallet — an <b>EIP-3009</b> authorization for USD₮0 on X Layer.</li>
<li>Repeat the call with the <code>PAYMENT-SIGNATURE</code> header. Payment settles on chain and the
deliverable comes back in the same response.</li>
</ol>
<p style="color:var(--dim);font-size:14px;margin:2px 0 0">Stablecoin transfers on X Layer are gas-free,
so a call costs exactly its listed price. Sending an empty body to any endpoint returns its input
contract instead of an error, so you can discover the shape before paying.</p>

<h2>Verifying a report</h2>
<div class="meta">
<div><dt>Signer address</dt><dd>{signer_line}</dd></div>
<div><dt>Signing scheme</dt><dd>EIP-191 personal_sign over sha256(canonical_json)</dd></div>
<div><dt>Network</dt><dd>X Layer · eip155:196</dd></div>
<div><dt>Asset</dt><dd>USD₮0 · 0x779ded0c9e1022225f8e0630b35a9b54be713736</dd></div>
<div><dt>Model preference</dt><dd>{model}</dd></div>
<div><dt>Key + health</dt><dd><a href="/.well-known/reach-signer">/.well-known/reach-signer</a> ·
<a href="/health">/health</a></dd></div>
</div>
<p style="color:var(--dim);font-size:14px;margin:13px 0 0">Recover the signer from
<code>signed.signature</code> over <code>signed.message_sha256</code> and require it to equal the address
above. A report recovering to any other address was not issued by Reach. You can also POST a report back
to <code>/receipt/verify</code> and have it checked for you.</p>

<footer>Reach is an Agent Service Provider on OKX.AI. Autonomous research over live sources —
verify the caveats yourself. Not financial advice.</footer>
</div></body></html>"""
