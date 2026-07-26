/**
 * Reach ASP — x402 pay-per-call gateway.
 *
 * A thin front for the Python Reach engine. It reuses OKX's official Agent-Payments (x402) SDK — the
 * exact integration OKX's marketplace validates against, and the same one Aletheia passed — then proxies
 * the paid call through to the FastAPI engine on localhost. Nothing about payments is re-implemented.
 *
 * Public → Caddy (TLS, reach.ivaronix.xyz) → THIS gateway (127.0.0.1:8791) → Reach FastAPI (127.0.0.1:8790).
 *
 * Two hard-won details baked in (verified with OKX's own `onchainos agent x402-check`): route keys carry no
 * method prefix so the paywall answers 402 on OKX's bare-GET availability probe (not 404/405), and each
 * accepts entry publishes `decimals:6` so OKX can resolve the USD₮0 price (it isn't in OKX's token list).
 */
import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { OKXFacilitatorClient } from "@okxweb3/app-x402-core";
import { x402ResourceServer, x402HTTPResourceServer, paymentMiddlewareFromHTTPServer } from "@okxweb3/app-x402-hono";
import { ExactEvmScheme } from "@okxweb3/app-x402-evm/exact/server";
import type { MiddlewareHandler } from "hono";
import { timingSafeEqual } from "node:crypto";

const NETWORK = "eip155:196" as const; // X Layer
const PAY_TO = process.env.X402_PAY_TO || "";
const OKX_API_KEY = process.env.OKX_API_KEY || "";
const OKX_SECRET_KEY = process.env.OKX_SECRET_KEY || "";
const OKX_PASSPHRASE = process.env.OKX_PASSPHRASE || "";
const BACKEND = (process.env.REACH_BACKEND || "http://127.0.0.1:8790").replace(/\/$/, "");
const INTERNAL_SECRET = process.env.REACH_INTERNAL_SECRET || "";

const OKX_PAY_ENABLED = !!(
  process.env.X402_ENABLED === "1" && PAY_TO && OKX_API_KEY && OKX_SECRET_KEY && OKX_PASSPHRASE
);

/** Reach's paid A2MCP services — prices match the OKX listing. Keys carry NO HTTP-method prefix on
 *  purpose: the OKX SDK treats a spaceless route key as verb "*" (matches ANY method), so the paywall
 *  returns the standard 402 challenge even for OKX's method-agnostic availability probe (a bare GET with
 *  no body). A "POST " prefix makes that probe miss the route and fall through to 405 — failing validation. */
const ROUTES = {
  "/research": {
    accepts: { scheme: "exact" as const, network: NETWORK, payTo: PAY_TO, price: "$0.05", maxTimeoutSeconds: 300, extra: { decimals: 6 } },
    description: "Reach Deep Research - an autonomous, multi-round web investigation for any question: it searches, reads full-text sources (including JavaScript-rendered pages), cross-checks, and returns a report where every claim is cited to a source it read. Use for a complete answer; for a single known URL use /read, for just ranked links use /search. The whole report is EIP-191 signed so the signer can be verified offline. Input: {question}. Returns: {report, cited_sources[], sources[], signed}.",
    mimeType: "application/json",
  },
  "/research/stream": {
    accepts: { scheme: "exact" as const, network: NETWORK, payTo: PAY_TO, price: "$0.05", maxTimeoutSeconds: 300, extra: { decimals: 6 } },
    description: "Reach Deep Research (streaming) - the same cited, EIP-191-signed research as /research, streamed as Server-Sent Events (live tool calls, then the final report). Use when you want to show research progress live rather than wait for one JSON response. Input: {question}. Returns: SSE events, then the final signed report.",
    mimeType: "application/json",
  },
  "/read": {
    accepts: { scheme: "exact" as const, network: NETWORK, payTo: PAY_TO, price: "$0.01", maxTimeoutSeconds: 120, extra: { decimals: 6 } },
    description: "Reach Read - fetch and clean-read ONE web page as text (headless-browser fallback for JavaScript-rendered pages), with a citation. Use when you already have a URL and need its full text. To find URLs first use /search; for a multi-source answer use /research. Input: {url, max_chars?}. Returns: {content, sources[]}.",
    mimeType: "application/json",
  },
  "/search": {
    accepts: { scheme: "exact" as const, network: NETWORK, payTo: PAY_TO, price: "$0.01", maxTimeoutSeconds: 120, extra: { decimals: 6 } },
    description: "Reach Search - live open-web search returning ranked results (title, URL, snippet). Use to discover sources for a query, then /read the promising ones - or use /research to do the whole investigation. Input: {query, num?}. Returns: {results, sources[]}.",
    mimeType: "application/json",
  },
};

let resourceServer: { initialize(): Promise<void> } | null = null;

/** Mirror the x402 challenge into the 402 response BODY via the SDK's documented `unpaidResponseBody`
 *  hook (the mechanism the live competitor Argus uses). The SDK emits the PAYMENT-REQUIRED header
 *  itself, so header- and body-reading clients — and OKX's `x402-check` — all see a complete
 *  challenge. Also injects `decimals: 6` (USD₮0 isn't in OKX's token list). Replaces the hand-rolled
 *  Hono override that could silently revert the header. */
function mirrorChallenge(accepts: { scheme: string; network: typeof NETWORK; payTo: string; price: string; maxTimeoutSeconds: number }, description: string, mimeType: string) {
  return async (context: any) => {
    const rs: any = resourceServer;
    const requirements = await rs.buildPaymentRequirementsFromOptions([accepts], context);
    const url = context?.adapter?.getUrl?.() ?? "";
    const paymentRequired = await rs.createPaymentRequiredResponse(requirements, { url, description, mimeType }, "Payment required");
    if (Array.isArray(paymentRequired?.accepts)) {
      for (const a of paymentRequired.accepts) {
        if (a && typeof a === "object") {
          // decimals belongs in `extra` (the SDK-supported location OKX's validator reads); a top-level
          // `decimals` field is dropped by OKX's canonical re-serialization, so put it ONLY here.
          a.extra = { ...(a.extra ?? {}), decimals: 6 };
        }
      }
    }
    return { contentType: "application/json", body: paymentRequired };
  };
}

function buildOkxPayMiddleware(): MiddlewareHandler {
  const facilitatorClient = new OKXFacilitatorClient({
    apiKey: OKX_API_KEY, secretKey: OKX_SECRET_KEY, passphrase: OKX_PASSPHRASE,
    baseUrl: process.env.OKX_BASE_URL || "https://web3.okx.com",
    syncSettle: false,
  });
  const rs = new x402ResourceServer(facilitatorClient).register(NETWORK, new ExactEvmScheme());
  resourceServer = rs;
  const ROUTES_WITH_MIRROR = Object.fromEntries(
    Object.entries(ROUTES).map(([k, v]) => [k, { ...v, unpaidResponseBody: mirrorChallenge(v.accepts, v.description, v.mimeType) }])
  );
  const httpServer = new x402HTTPResourceServer(rs, ROUTES_WITH_MIRROR as any);
  httpServer.onProtectedRequest(async (ctx) => {
    const h = (name: string) => ctx.adapter.getHeader(name) || "";
    // Fail-closed: the ONLY unpaid bypass is the server-only x-reach-internal secret (Reach's own
    // site/demo/daemon), constant-time compared. Browser-forgeable headers (Sec-Fetch-Site / Origin /
    // Referer / Host) are NOT trusted — any HTTP client can forge them, which would hand an agent or the
    // OKX validator the paid result for free (a non-compliant x402 endpoint).
    const presented = h("x-reach-internal");
    if (INTERNAL_SECRET.length > 0 && presented.length === INTERNAL_SECRET.length &&
        timingSafeEqual(Buffer.from(INTERNAL_SECRET), Buffer.from(presented))) return { grantAccess: true };
    return; // everyone else — agents, marketplace, validator, browser demo — pays (standard 402)
  });

  /**
   * Turn a THROW during payment verification into a clean 402 re-challenge.
   *
   * A structurally valid but forged PAYMENT-SIGNATURE (correct base64 JSON, bogus signature) makes the
   * facilitator's verify step throw, and an uncaught throw reaches Hono as a bare
   * `500 Internal Server Error` — measured on all three of our ASPs before this guard. It fails CLOSED
   * (no free work is ever served), but 500 is the wrong answer to "your payment did not verify".
   *
   * Rather than hand-roll a challenge and risk drifting from the SDK's shape, re-enter the middleware
   * with the payment headers stripped: to the SDK the call is simply unpaid, so it emits its own
   * canonical 402 — PAYMENT-REQUIRED header and mirrored body both.
   *
   * A throw from the PAID handler downstream is rethrown untouched: that caller has paid, and a 402
   * would tell them to pay twice.
   */
  const PAYMENT_HEADERS = ["payment-signature", "x-payment", "payment"];
  const guard = (inner: MiddlewareHandler): MiddlewareHandler => async (c, next) => {
    const method = c.req.method;
    const body = method === "GET" || method === "HEAD" ? undefined : await c.req.raw.clone().arrayBuffer();
    let entered = false;
    try {
      return await inner(c, async () => { entered = true; await next(); });
    } catch (e) {
      if (entered) throw e;
      console.warn(`[reach-gateway] payment verification threw on ${new URL(c.req.url).pathname}: ${(e as Error)?.message ?? e}`);
      try {
        const headers = new Headers(c.req.raw.headers);
        for (const h of PAYMENT_HEADERS) headers.delete(h);
        c.req.raw = new Request(c.req.url, { method, headers, body });
        return await inner(c, async () => {
          throw new Error("payment middleware granted access to an unpaid re-challenge");
        });
      } catch {
        return c.json({ error: "invalid_payment",
                        detail: "PAYMENT-SIGNATURE did not verify. Retry with no payment header to get a fresh challenge." },
                      402);
      }
    }
  };
  return guard(paymentMiddlewareFromHTTPServer(httpServer));
}

const app = new Hono();

/**
 * CORS, mounted FIRST so a preflight short-circuits ahead of the paywall.
 *
 * A preflight carries no payment by definition, so a paywall that sees OPTIONS answers 402 — the
 * preflight fails and the real request can never be made from a browser-based or cross-origin agent.
 * Without Access-Control-Expose-Headers a browser also cannot READ the PAYMENT-REQUIRED header on the
 * 402, so it cannot construct a payment at all: the x402 flow is invisible to it.
 *
 * Measured against a listed, transacting ASP (ShieldSuite #4959) which answers OPTIONS 204 and exposes
 * PAYMENT-REQUIRED / PAYMENT-RESPONSE. All three of ours returned 402 to a preflight with no
 * access-control headers.
 */
const CORS: Record<string, string> = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,OPTIONS",
  "access-control-allow-headers": "Content-Type,Authorization,X-PAYMENT,PAYMENT-SIGNATURE",
  "access-control-expose-headers": "PAYMENT-REQUIRED,PAYMENT-RESPONSE,X-PAYMENT-RESPONSE",
  "access-control-max-age": "86400",
};

app.use("*", async (c, next) => {
  if (c.req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  await next();
  c.res.headers.set("access-control-allow-origin", CORS["access-control-allow-origin"]!);
  c.res.headers.set("access-control-allow-headers", CORS["access-control-allow-headers"]!);
  c.res.headers.set("access-control-expose-headers", CORS["access-control-expose-headers"]!);
});

if (OKX_PAY_ENABLED) {
  app.use("*", async (c, next) => {
    // Behind Caddy the request reaches us as http (TLS is terminated at the edge). Rewrite to https when
    // the edge saw https (X-Forwarded-Proto) BEFORE the payment middleware reads the URL, so the x402
    // challenge's resource.url is https — as OKX requires.
    try {
      const proto = c.req.header("x-forwarded-proto") || "";
      if (proto.includes("https") && c.req.url.startsWith("http://")) {
        c.req.raw = new Request(c.req.url.replace(/^http:\/\//, "https://"), c.req.raw);
      }
    } catch { /* leave the request untouched on any edge case */ }
    await next();
    // The 402 challenge + body-mirror + decimals are now produced natively by the SDK's documented
    // `unpaidResponseBody` hook (see buildOkxPayMiddleware) — header by the SDK, body by the hook — so
    // there is no hand-rolled 402 override here to fight Hono's `set res` header-merge.
  });
  app.use("*", buildOkxPayMiddleware());
}

/** Once access is granted (paid or free), proxy the request straight to the Python Reach engine. */
app.all("*", async (c) => {
  const url = new URL(c.req.url);
  const target = BACKEND + url.pathname + url.search;
  const method = c.req.method;
  // Bound the forward call so a slow or hung Python backend can never hang the paywall past the x402
  // window advertised for this path (aborts → 502 instead of hanging OKX's test). 10s transit margin.
  const windowSec = (ROUTES as Record<string, { accepts: { maxTimeoutSeconds: number } }>)[url.pathname]?.accepts.maxTimeoutSeconds ?? 300;
  const forwardTimeoutMs = Math.max(5_000, windowSec * 1000 - 10_000);
  const init: RequestInit = {
    method,
    headers: { "content-type": c.req.header("content-type") || "application/json" },
    body: method === "GET" || method === "HEAD" ? undefined : await c.req.arrayBuffer(),
    signal: AbortSignal.timeout(forwardTimeoutMs),
  };
  try {
    const r = await fetch(target, init);
    const headers = new Headers();
    const ct = r.headers.get("content-type");
    if (ct) headers.set("content-type", ct);
    return new Response(r.body, { status: r.status, headers });
  } catch (e: any) {
    return c.json({ error: "backend_unreachable", detail: e?.message ?? String(e) }, 502);
  }
});

const DEV_OPEN = process.env.REACH_DEV_OPEN === "1";
if (!OKX_PAY_ENABLED && !DEV_OPEN) {
  // Fail-closed: never start serving paid routes for free in production. Require the full x402 config
  // (X402_ENABLED=1 + OKX_API_KEY/OKX_SECRET_KEY/OKX_PASSPHRASE + X402_PAY_TO). REACH_DEV_OPEN=1 is the
  // explicit local-dev-only escape hatch — it must never be set in production.
  console.error("[reach-gateway] REFUSING TO START — x402 is not fully configured and REACH_DEV_OPEN is not set. Set X402_ENABLED=1 + OKX_API_KEY/OKX_SECRET_KEY/OKX_PASSPHRASE + X402_PAY_TO for production, or REACH_DEV_OPEN=1 for local dev.");
  process.exit(1);
}
const port = Number(process.env.GATEWAY_PORT || 8791);
serve({ fetch: app.fetch, port, hostname: "127.0.0.1" });
console.log(`[reach-gateway] listening on 127.0.0.1:${port} → backend ${BACKEND} · x402 ${OKX_PAY_ENABLED ? "ON" : "OFF"}`);
if (resourceServer) {
  resourceServer.initialize()
    .then(() => console.log("[reach-gateway] facilitator initialized — x402 live on /research /read /search"))
    .catch((e) => console.error("[reach-gateway] facilitator init failed:", (e as Error)?.message ?? e));
}
