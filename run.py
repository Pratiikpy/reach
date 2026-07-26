"""Run a real research question through Reach and print the report. Test like a real user.

Usage: python run.py "your research question here"
"""
import json
import os
import sys
import time

# Windows console is cp1252 by default — force UTF-8 so unicode in reports never crashes.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# load ZG_COMPUTE_API_KEY + signer key from the verity .env if present
def _load_env():
    envp = os.path.join(os.path.dirname(__file__), "..", "verity", ".env")
    envp = os.path.abspath(envp)
    if os.path.exists(envp):
        for line in open(envp, encoding="utf-8", errors="replace"):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

_load_env()

from reach.agent import deep_research  # noqa: E402


def on_event(kind, data):
    t = time.strftime("%H:%M:%S")
    if kind == "tool":
        args = data.get("args", {})
        arg = args.get("query") or args.get("url") or ""
        print(f"  [{t}] round {data['round']}: TOOL {data['name']}({arg[:70]})", flush=True)
    elif kind == "assistant":
        if data.get("text"):
            print(f"  [{t}] round {data['round']}: THINK {data['text'][:160]}", flush=True)


def main():
    q = " ".join(sys.argv[1:]).strip() or "What is OKX X Layer and what are people actually saying about it?"
    print(f"\n=== REACH DEEP RESEARCH ===\nQ: {q}\n" + "-" * 60, flush=True)
    t0 = time.time()
    res = deep_research(q, on_event=on_event)
    dt = time.time() - t0

    print("\n" + "=" * 60)
    print(res["report"])
    print("=" * 60)
    print(f"\nrounds: {res['rounds']} | tools used: {res['tools_used']} | reached: {res['reaches']}")
    print(f"sources touched: {len(res['sources'])} | cited: {len(res['cited_sources'])}")
    print(f"TEE verified: {res['tee_verified']} | signed by: {(res['signed'] or {}).get('signer','(no key)')}")
    print(f"model: {res['model']} | time: {dt:.0f}s")
    # dump full json next to the run for inspection
    out = os.path.join(os.path.dirname(__file__), "last_run.json")
    json.dump(res, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print(f"full result -> {out}")


if __name__ == "__main__":
    main()
